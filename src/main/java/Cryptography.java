import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;

public final class Cryptography {

    private static final byte[] BLIND_KEY;

    static {
        String b64 = PropertiesProvider.PROPS.getProperty("blind_index_key");
        if (b64 == null || b64.isBlank()) {
            byte[] fresh = new byte[32];
            new SecureRandom().nextBytes(fresh);
            String encoded = Base64.getEncoder().encodeToString(fresh);
            System.err.println("======================================================================");
            System.err.println("No blind_index_key found in Password.properties.");
            System.err.println("Generated a new one — paste this into Password.properties and re-run:");
            System.err.println();
            System.err.println("blind_index_key=" + encoded);
            System.err.println("======================================================================");
            throw new IllegalStateException("blind_index_key not configured");
        }
        try {
            BLIND_KEY = Base64.getDecoder().decode(b64);
            if (BLIND_KEY.length < 32) {
                throw new IllegalStateException("blind_index_key must decode to at least 32 bytes");
            }
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("blind_index_key is not valid Base64", e);
        }
    }

    private Cryptography() {}

    /** HMAC-SHA256(BLIND_KEY, normalized(plaintext)) as lowercase hex. */
    public static String blindIndex(String plaintext) {
        if (plaintext == null) plaintext = "";
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(BLIND_KEY, "HmacSHA256"));
            byte[] out = mac.doFinal(plaintext.trim().toLowerCase(Locale.ROOT)
                    .getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(out);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC failure", e);
        }
    }
}
