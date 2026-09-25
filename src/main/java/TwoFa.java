import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.qrcode.QRCodeWriter;
import org.apache.commons.codec.binary.Base32;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.awt.Desktop;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;

public final class TwoFa {

    private static final Duration STEP = Duration.ofSeconds(30);

    private TwoFa() {}

    public static String generateSecret() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA1");
            keyGen.init(160);
            SecretKey secretKey = keyGen.generateKey();
            return new Base32().encodeToString(secretKey.getEncoded());
        } catch (Exception e) {
            throw new IllegalStateException("Could not generate TOTP secret", e);
        }
    }

    public record VerifyResult(boolean ok, long step) {
        public static final VerifyResult FAIL = new VerifyResult(false, -1);
    }

    public static VerifyResult verify(String base32Secret, String code, long lastAcceptedStep) {
        if (code == null || !code.matches("\\d{6}")) return VerifyResult.FAIL;
        try {
            byte[] keyBytes = new Base32().decode(base32Secret);
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "HmacSHA1");
            TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator();

            Instant now = Instant.now();
            long currentStep = now.getEpochSecond() / STEP.toSeconds();

            byte[] presented = code.getBytes(StandardCharsets.US_ASCII);
            for (int delta = -1; delta <= 1; delta++) {
                long step = currentStep + delta;
                if (step <= lastAcceptedStep) continue; // replay defense
                Instant at = Instant.ofEpochSecond(step * STEP.toSeconds());
                String candidate = String.format("%06d", totp.generateOneTimePassword(keySpec, at));
                byte[] candidateBytes = candidate.getBytes(StandardCharsets.US_ASCII);
                if (MessageDigest.isEqual(candidateBytes, presented)) {
                    return new VerifyResult(true, step);
                }
            }
            return VerifyResult.FAIL;
        } catch (Exception e) {
            return VerifyResult.FAIL;
        }
    }

    public static void generateQRCode(String username, String base32Secret) {
        String issuer = "PasswordManager";
        String otpAuthUrl;
        try {
            otpAuthUrl = String.format(
                    "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
                    URLEncoder.encode(issuer, StandardCharsets.UTF_8),
                    URLEncoder.encode(username, StandardCharsets.UTF_8),
                    base32Secret,
                    URLEncoder.encode(issuer, StandardCharsets.UTF_8));
        } catch (Exception e) {
            System.err.println("Failed to build otpauth URL.");
            return;
        }

        try {
            var matrix = new QRCodeWriter().encode(otpAuthUrl, BarcodeFormat.QR_CODE, 300, 300);
            Path out = Files.createTempFile("totp-", ".png");
            out.toFile().deleteOnExit(); // PNG contains the TOTP secret
            MatrixToImageWriter.writeToPath(matrix, "PNG", out);
            System.out.println("QR code saved at: " + out.toAbsolutePath());
            System.out.println("Manual-entry secret (if you can't scan): " + base32Secret);
            if (Desktop.isDesktopSupported()) {
                try { Desktop.getDesktop().open(out.toFile()); } catch (Exception ignore) {}
            }
        } catch (Exception e) {
            System.err.println("Failed to render QR code locally. Manual-entry secret: " + base32Secret);
        }
    }
}
