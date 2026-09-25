import java.security.SecureRandom;
import java.util.Locale;
import java.util.Scanner;

public final class PasswordValidator {

    private static final int MIN_LEN = 12;
    private static final SecureRandom RNG = new SecureRandom();

    private static final String UPPER  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWER  = "abcdefghijklmnopqrstuvwxyz";
    private static final String DIGITS = "0123456789";
    private static final String SPECIAL = "!#$%&/()=?^@{[]}+-_.:,;";
    private static final String ALL    = UPPER + LOWER + DIGITS + SPECIAL;

    private PasswordValidator() {}

    public static String validatePassword(Scanner scan, Session session) {
        while (true) {
            char[] pwdChars = PasswordDB.readPasswordChars(scan, "Enter password (or blank to cancel): ");
            String password = new String(pwdChars);
            java.util.Arrays.fill(pwdChars, '\0');
            if (password.isEmpty()) return null;

            if (password.length() < MIN_LEN) {
                System.out.println("- Password must be at least " + MIN_LEN + " characters.");
                continue;
            }

            int pwned = HaveIBeenPwn.checkPassword(password);
            if (pwned > 0) {
                System.out.println("- This password appears in known breaches (" + pwned + " hits). Choose another.");
                continue;
            }

            System.out.println("- Password is valid"
                    + (password.length() >= 16 ? " and strong." : "."));
            System.out.println(pwned == 0
                    ? "- Found in 0 known breaches (Have I Been Pwned)."
                    : "- Breach count unavailable (could not reach Have I Been Pwned).");
            if (offerSave(scan, session, password)) continue; // "try again"
            return password;
        }
    }

    public static String generatePassword(Scanner scan, Session session) {
        int len = -1;
        while (len < MIN_LEN) {
            System.out.print("Enter password length (minimum " + MIN_LEN + "): ");
            String line = scan.nextLine().trim();
            try {
                len = Integer.parseInt(line);
            } catch (NumberFormatException e) {
                len = -1;
            }
            if (len < MIN_LEN) System.out.println("Length must be >= " + MIN_LEN + ".");
        }

        while (true) {
            // Guarantee one of each class while keeping uniform randomness elsewhere.
            char[] buf = new char[len];
            buf[0] = UPPER.charAt(RNG.nextInt(UPPER.length()));
            buf[1] = LOWER.charAt(RNG.nextInt(LOWER.length()));
            buf[2] = DIGITS.charAt(RNG.nextInt(DIGITS.length()));
            buf[3] = SPECIAL.charAt(RNG.nextInt(SPECIAL.length()));
            for (int i = 4; i < len; i++) {
                buf[i] = ALL.charAt(RNG.nextInt(ALL.length()));
            }
            // Fisher-Yates shuffle so the class-guarantee chars are not always at the start.
            for (int i = buf.length - 1; i > 0; i--) {
                int j = RNG.nextInt(i + 1);
                char t = buf[i]; buf[i] = buf[j]; buf[j] = t;
            }

            String password = new String(buf);
            java.util.Arrays.fill(buf, '\0');
            System.out.println("Generated password: " + password);
            if (offerSave(scan, session, password)) continue; // "try again" -> regenerate
            return password;
        }
    }

    /** Ask whether to save the password (or regenerate / return to menu). Returns true for "try again". */
    private static boolean offerSave(Scanner scan, Session session, String password) {
        while (true) {
            System.out.println("Save it, try again, or return to menu? (save / try again / menu)");
            UserAction choice = UserAction.fromInput(scan.nextLine());
            if (choice == null) {
                System.out.println("Invalid input.");
                continue;
            }
            switch (choice) {
                case SAVE -> { PasswordDB.saveGeneratedPassword(scan, session, password); return false; }
                case TRY_AGAIN -> { return true; }
                case MENU -> { return false; }
                default -> System.out.println("Invalid choice.");
            }
        }
    }
}
