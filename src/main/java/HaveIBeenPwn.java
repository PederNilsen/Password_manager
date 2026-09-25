import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Have-I-Been-Pwned password range API client (k-anonymity).
 * Only the first 5 hex chars of the SHA-1 hash leave this machine.
 */
public final class HaveIBeenPwn {

    private static final Logger LOG = Logger.getLogger("HaveIBeenPwn");
    private static final int TIMEOUT_MS = 10_000;

    private HaveIBeenPwn() {}

    public static void checkPasswordPwned(Scanner scan) {
        // Use console (no echo) when available — passwords should never be visible on screen.
        char[] pwd = PasswordDB.readPasswordChars(scan, "Enter a password to check: ");
        try {
            if (pwd.length == 0) {
                System.out.println("Invalid password.");
                return;
            }
            System.out.println("Checking…");
            int count = checkPassword(new String(pwd));
            if (count > 0) {
                System.out.println("WARNING: this password appears " + count + " times in known breaches. Do NOT use it.");
            } else if (count == 0) {
                System.out.println("Good news — this password was not found in known breaches.");
            } else {
                System.out.println("Could not check the password. Try again later.");
            }
        } finally {
            Arrays.fill(pwd, '\0');
        }
    }

    /** Returns the breach count, or -1 on transport failure. */
    public static int checkPassword(String password) {
        HttpURLConnection conn = null;
        try {
            String sha1 = sha1Hex(password).toUpperCase();
            String prefix = sha1.substring(0, 5);
            String suffix = sha1.substring(5);

            URI uri = URI.create("https://api.pwnedpasswords.com/range/" + prefix);
            conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("User-Agent", "JavaPasswordManager");
            conn.setRequestProperty("Add-Padding", "true");
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);

            if (conn.getResponseCode() != 200) return -1;

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    int colon = line.indexOf(':');
                    if (colon < 0) continue;
                    if (line.regionMatches(true, 0, suffix, 0, colon)
                            && colon == suffix.length()) {
                        try { return Integer.parseInt(line.substring(colon + 1).trim()); }
                        catch (NumberFormatException nfe) { return -1; }
                    }
                }
                return 0;
            }
        } catch (Exception e) {
            LOG.log(Level.FINE, "HIBP lookup failed");
            return -1;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private static String sha1Hex(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder(hash.length * 2);
        for (byte b : hash) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
