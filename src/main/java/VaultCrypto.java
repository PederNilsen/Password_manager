import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Per-user Data-Encryption-Key (DEK) crypto.
 *
 *  master password ──Argon2id(salt)──▶ KEK ──AES-GCM unwrap──▶ DEK
 *                                                              │
 *                                                              ▼
 *  recovery code   ──Argon2id(salt)──▶ recovery KEK ──unwrap──▶ DEK
 *                                                              │
 *                                                              ▼
 *                       vault items, TOTP secret, username (AES-GCM under DEK)
 *
 *  - The master password and recovery code never touch persistent storage.
 *  - The DEK lives only in {@link Session} memory and is zeroed on logout.
 *  - kdf_params is stored alongside the salt so parameters can be upgraded
 *    over time without re-deriving every user's KEK eagerly.
 *  - AEAD failure (bad tag) IS the wrong-password signal. No separate hash.
 */
public final class VaultCrypto {

    public static final String DEFAULT_KDF_PARAMS = "argon2id,m=65536,t=3,p=1,v=19";
    private static final int DEK_BYTES   = 32;   // AES-256
    private static final int SALT_BYTES  = 16;
    private static final int GCM_IV_LEN  = 12;
    private static final int GCM_TAG_BITS = 128;

    private static final SecureRandom RNG = new SecureRandom();

    private VaultCrypto() {}

    // ---------- KDF ----------

    public static byte[] randomSalt() {
        byte[] s = new byte[SALT_BYTES];
        RNG.nextBytes(s);
        return s;
    }

    public static byte[] newDek() {
        byte[] dek = new byte[DEK_BYTES];
        RNG.nextBytes(dek);
        return dek;
    }

    /** Derive a 32-byte key from a password using Argon2id with given params. */
    public static byte[] deriveKey(char[] password, byte[] salt, String kdfParams) {
        Params p = Params.parse(kdfParams);
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(p.version)
                .withSalt(salt)
                .withMemoryAsKB(p.memoryKB)
                .withIterations(p.iterations)
                .withParallelism(p.parallelism)
                .build();
        Argon2BytesGenerator g = new Argon2BytesGenerator();
        g.init(params);
        byte[] out = new byte[32];
        g.generateBytes(password, out);
        return out;
    }

    /**
     * Burn KDF time even when the user does not exist, so login latency
     * does not reveal username existence. Result is discarded.
     */
    public static void dummyDerive(String kdfParams) {
        deriveKey("dummy-password".toCharArray(),
                  new byte[SALT_BYTES],
                  kdfParams);
    }

    // ---------- Wrap / unwrap ----------

    /** Encrypt the DEK under a KEK using AES-GCM; returns base64(iv || ct || tag). */
    public static String wrapDek(byte[] dek, byte[] kek) {
        return encryptRaw(dek, kek);
    }

    /** Decrypt a wrapped DEK; throws if the KEK is wrong (AEAD tag failure). */
    public static byte[] unwrapDek(String wrappedB64, byte[] kek) throws AEADBadTagException {
        try {
            return decryptRaw(wrappedB64, kek);
        } catch (AEADBadTagException e) {
            throw e;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unwrap failed", e);
        }
    }

    // ---------- Field encryption under the DEK ----------

    public static String encrypt(String plaintext, byte[] dek) {
        if (plaintext == null) plaintext = "";
        return encryptRaw(plaintext.getBytes(StandardCharsets.UTF_8), dek);
    }

    public static String decrypt(String ciphertextB64, byte[] dek) {
        if (ciphertextB64 == null || ciphertextB64.isEmpty()) return "";
        try {
            byte[] pt = decryptRaw(ciphertextB64, dek);
            return new String(pt, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Decrypt failed", e);
        }
    }

    private static String encryptRaw(byte[] plaintext, byte[] key) {
        try {
            byte[] iv = new byte[GCM_IV_LEN];
            RNG.nextBytes(iv);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] ct = c.doFinal(plaintext);
            ByteBuffer buf = ByteBuffer.allocate(iv.length + ct.length);
            buf.put(iv).put(ct);
            return Base64.getEncoder().encodeToString(buf.array());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Encrypt failed", e);
        }
    }

    private static byte[] decryptRaw(String ciphertextB64, byte[] key) throws GeneralSecurityException {
        byte[] all = Base64.getDecoder().decode(ciphertextB64);
        if (all.length < GCM_IV_LEN + (GCM_TAG_BITS / 8)) {
            throw new GeneralSecurityException("Ciphertext too short");
        }
        byte[] iv = Arrays.copyOfRange(all, 0, GCM_IV_LEN);
        byte[] ct = Arrays.copyOfRange(all, GCM_IV_LEN, all.length);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(GCM_TAG_BITS, iv));
        return c.doFinal(ct);
    }

    // ---------- KDF param parsing ----------

    private record Params(int memoryKB, int iterations, int parallelism, int version) {
        static Params parse(String s) {
            // Expected: "argon2id,m=65536,t=3,p=1,v=19"
            int m = 65536, t = 3, p = 1, v = Argon2Parameters.ARGON2_VERSION_13;
            for (String part : s.split(",")) {
                String tok = part.trim();
                if (tok.startsWith("m=")) m = Integer.parseInt(tok.substring(2));
                else if (tok.startsWith("t=")) t = Integer.parseInt(tok.substring(2));
                else if (tok.startsWith("p=")) p = Integer.parseInt(tok.substring(2));
                else if (tok.startsWith("v=")) v = Integer.parseInt(tok.substring(2));
            }
            return new Params(m, t, p, v);
        }
    }
}
