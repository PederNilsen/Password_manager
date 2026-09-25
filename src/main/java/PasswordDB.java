import javax.crypto.AEADBadTagException;
import java.io.Console;
import java.security.SecureRandom;
import java.sql.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class PasswordDB {

    private static final Logger LOG = Logger.getLogger("PasswordDB");
    private static final SecureRandom RNG = new SecureRandom();

    private static final String JDBC_URL;
    private static final String DB_USER;
    private static final String DB_PWD;

    private static final int MAX_FAILED_LOGINS = 5;
    private static final int LOCKOUT_MINUTES   = 15;
    private static final int RECOVERY_CODE_BYTES = 16; // 128-bit, base32

    static {
        DB_USER = PropertiesProvider.PROPS.getProperty("host");
        DB_PWD  = PropertiesProvider.PROPS.getProperty("pwd");
        String db = PropertiesProvider.PROPS.getProperty("db_name");
        String port = PropertiesProvider.PROPS.getProperty("port");
        // Localhost-friendly TLS settings:
        //   useSSL=true                    — prefer TLS for the JDBC handshake
        //   verifyServerCertificate=false  — accept the self-signed cert MySQL ships
        //                                    (safe ONLY because we connect to localhost)
        //   allowPublicKeyRetrieval=true   — required for caching_sha2_password auth
        //                                    when TLS verification is off
        // For a non-localhost deployment, pin a real CA and flip these back.
        JDBC_URL = "jdbc:mysql://localhost:" + port + "/" + db
                + "?useSSL=true&verifyServerCertificate=false&allowPublicKeyRetrieval=true"
                + "&serverTimezone=UTC&connectionCollation=utf8mb4_unicode_ci";
    }

    private PasswordDB() {}

    private static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(JDBC_URL, DB_USER, DB_PWD);
    }

    // ===================================================================
    //  Account creation
    // ===================================================================

    public static void createUser(Scanner scan) {
        System.out.print("Enter your username: ");
        String username = scan.nextLine().trim().toLowerCase(Locale.ROOT);
        if (username.isEmpty()) { System.out.println("Username cannot be empty."); return; }

        String usernameHmac = Cryptography.blindIndex(username);

        // Reject duplicates up front (the UNIQUE constraint also catches it).
        try (Connection conn = getConnection();
             PreparedStatement check = conn.prepareStatement(
                     "SELECT 1 FROM users WHERE username_hmac = ?")) {
            check.setString(1, usernameHmac);
            try (ResultSet rs = check.executeQuery()) {
                if (rs.next()) { System.out.println("Username already taken."); return; }
            }
        } catch (SQLException e) {
            LOG.log(Level.WARNING, "DB error checking username uniqueness", e);
            System.out.println("Could not create account, please try again later.");
            return;
        }

        char[] password = null;
        try {
            password = readMatchingPassword(scan);
            if (password == null) return;

            // Per-user crypto material.
            byte[] kdfSalt = VaultCrypto.randomSalt();
            byte[] kek     = VaultCrypto.deriveKey(password, kdfSalt, VaultCrypto.DEFAULT_KDF_PARAMS);
            byte[] dek     = VaultCrypto.newDek();
            String wrappedDek = VaultCrypto.wrapDek(dek, kek);
            Arrays.fill(kek, (byte) 0);

            // Recovery code (one base32 string, shown ONCE).
            byte[] recoveryRaw = new byte[RECOVERY_CODE_BYTES];
            RNG.nextBytes(recoveryRaw);
            String recoveryCode = new org.apache.commons.codec.binary.Base32().encodeAsString(recoveryRaw).replace("=", "");
            byte[] recoverySalt = VaultCrypto.randomSalt();
            byte[] recoveryKek  = VaultCrypto.deriveKey(recoveryCode.toCharArray(), recoverySalt,
                    VaultCrypto.DEFAULT_KDF_PARAMS);
            String wrappedDekRecovery = VaultCrypto.wrapDek(dek, recoveryKek);
            Arrays.fill(recoveryKek, (byte) 0);

            // TOTP enrollment.
            String totpSecret = TwoFa.generateSecret();
            String totpSecretEnc = VaultCrypto.encrypt(totpSecret, dek);
            String usernameEnc   = VaultCrypto.encrypt(username, dek);

            // Persist.
            try (Connection conn = getConnection();
                 PreparedStatement stmt = conn.prepareStatement(
                         "INSERT INTO users " +
                         "(username_hmac, username_enc, kdf_salt, kdf_params, wrapped_dek, " +
                         " recovery_salt, wrapped_dek_recovery, totp_secret_enc) " +
                         "VALUES (?, ?, ?, ?, ?, ?, ?, ?)")) {
                stmt.setString(1, usernameHmac);
                stmt.setString(2, usernameEnc);
                stmt.setString(3, Base64.getEncoder().encodeToString(kdfSalt));
                stmt.setString(4, VaultCrypto.DEFAULT_KDF_PARAMS);
                stmt.setString(5, wrappedDek);
                stmt.setString(6, Base64.getEncoder().encodeToString(recoverySalt));
                stmt.setString(7, wrappedDekRecovery);
                stmt.setString(8, totpSecretEnc);
                stmt.executeUpdate();
            }

            // Show recovery code ONCE. After this point we cannot show it again
            // because the DEK is only wrapped with it, never the code itself.
            System.out.println("=====================================================");
            System.out.println("ACCOUNT CREATED");
            System.out.println();
            System.out.println("Recovery code (store securely — shown ONCE, never again):");
            System.out.println("    " + recoveryCode);
            System.out.println();
            System.out.println("If you forget your master password, this code is the");
            System.out.println("only way to recover your vault. We cannot reset it for you.");
            System.out.println("=====================================================");

            TwoFa.generateQRCode(username, totpSecret);

            // Best-effort wipe.
            Arrays.fill(dek, (byte) 0);
            Arrays.fill(recoveryRaw, (byte) 0);
        } catch (SQLException e) {
            LOG.log(Level.WARNING, "DB error creating user", e);
            System.out.println("Could not create account, please try again later.");
        } finally {
            if (password != null) Arrays.fill(password, '\0');
        }
    }

    // ===================================================================
    //  Login
    // ===================================================================

    /** Returns an open {@link Session} on success, or null on failure. */
    public static Session login(Scanner scan) {
        System.out.print("Enter your username: ");
        String username = scan.nextLine().trim().toLowerCase(Locale.ROOT);
        char[] password = readPasswordChars(scan, "Enter your password: ");
        try {
            String usernameHmac = Cryptography.blindIndex(username);

            try (Connection conn = getConnection()) {
                UserRow row = loadUser(conn, usernameHmac);

                // Constant-time-ish: derive a dummy key when the user is missing.
                if (row == null) {
                    VaultCrypto.dummyDerive(VaultCrypto.DEFAULT_KDF_PARAMS);
                    System.out.println("Wrong username or password.");
                    return null;
                }

                if (row.locked) {
                    System.out.println("Account is temporarily locked. Try again later.");
                    return null;
                }

                byte[] kek = VaultCrypto.deriveKey(password, row.kdfSalt, row.kdfParams);
                byte[] dek;
                try {
                    dek = VaultCrypto.unwrapDek(row.wrappedDek, kek);
                } catch (AEADBadTagException badTag) {
                    Arrays.fill(kek, (byte) 0);
                    recordFailedLogin(conn, row.id, row.failedLogins);
                    System.out.println("Wrong username or password.");
                    return null;
                } finally {
                    // KEK is only needed for the unwrap; wipe it ASAP.
                    Arrays.fill(kek, (byte) 0);
                }

                // 2FA
                String totpSecret = VaultCrypto.decrypt(row.totpSecretEnc, dek);
                System.out.print("Enter 2FA code: ");
                String code = scan.nextLine().trim();
                TwoFa.VerifyResult vr = TwoFa.verify(totpSecret, code, row.lastTotpStep);
                if (!vr.ok()) {
                    Arrays.fill(dek, (byte) 0);
                    recordFailedLogin(conn, row.id, row.failedLogins);
                    System.out.println("Invalid 2FA code. Access denied.");
                    return null;
                }

                recordSuccessfulLogin(conn, row.id, vr.step());
                System.out.println("Login successful.");
                return new Session(row.id, username, dek);
            }
        } catch (SQLException e) {
            LOG.log(Level.WARNING, "DB error during login", e);
            System.out.println("Login failed, please try again later.");
            return null;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static UserRow loadUser(Connection conn, String usernameHmac) throws SQLException {
        String sql = "SELECT id, kdf_salt, kdf_params, wrapped_dek, totp_secret_enc, " +
                     "last_totp_step, failed_logins, " +
                     "(locked_until IS NOT NULL AND locked_until > NOW()) AS is_locked " +
                     "FROM users WHERE username_hmac = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, usernameHmac);
            try (ResultSet rs = stmt.executeQuery()) {
                if (!rs.next()) return null;
                UserRow r = new UserRow();
                r.id              = rs.getInt("id");
                r.kdfSalt         = Base64.getDecoder().decode(rs.getString("kdf_salt"));
                r.kdfParams       = rs.getString("kdf_params");
                r.wrappedDek      = rs.getString("wrapped_dek");
                r.totpSecretEnc   = rs.getString("totp_secret_enc");
                r.lastTotpStep    = rs.getLong("last_totp_step");
                r.failedLogins    = rs.getInt("failed_logins");
                r.locked          = rs.getBoolean("is_locked");
                return r;
            }
        }
    }

    private static void recordFailedLogin(Connection conn, int userId, int currentFailures) {
        int next = currentFailures + 1;
        String sql = (next >= MAX_FAILED_LOGINS)
                ? "UPDATE users SET failed_logins = 0, " +
                  "locked_until = DATE_ADD(NOW(), INTERVAL " + LOCKOUT_MINUTES + " MINUTE) WHERE id = ?"
                : "UPDATE users SET failed_logins = failed_logins + 1 WHERE id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, userId);
            stmt.executeUpdate();
        } catch (SQLException e) {
            LOG.log(Level.WARNING, "Failed to record login failure", e);
        }
    }

    private static void recordSuccessfulLogin(Connection conn, int userId, long acceptedStep) {
        try (PreparedStatement stmt = conn.prepareStatement(
                "UPDATE users SET failed_logins = 0, locked_until = NULL, " +
                "last_login = NOW(), last_totp_step = ? WHERE id = ?")) {
            stmt.setLong(1, acceptedStep);
            stmt.setInt(2, userId);
            stmt.executeUpdate();
        } catch (SQLException e) {
            LOG.log(Level.WARNING, "Failed to update successful login", e);
        }
    }

    // ===================================================================
    //  Recovery (forgot master password)
    // ===================================================================

    public static void resetMasterPasswordWithRecoveryCode(Scanner scan) {
        System.out.print("Enter your username: ");
        String username = scan.nextLine().trim().toLowerCase(Locale.ROOT);
        System.out.print("Enter your recovery code: ");
        String recoveryCode = scan.nextLine().replaceAll("\\s+", "").toUpperCase(Locale.ROOT);

        char[] newPwd = readMatchingPassword(scan);
        if (newPwd == null) return;

        try {
            try (Connection conn = getConnection()) {
                String sql = "SELECT id, recovery_salt, wrapped_dek_recovery, kdf_params " +
                             "FROM users WHERE username_hmac = ?";
                try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                    stmt.setString(1, Cryptography.blindIndex(username));
                    try (ResultSet rs = stmt.executeQuery()) {
                        if (!rs.next()) {
                            VaultCrypto.dummyDerive(VaultCrypto.DEFAULT_KDF_PARAMS);
                            System.out.println("Recovery failed.");
                            return;
                        }
                        int id = rs.getInt("id");
                        byte[] recSalt = Base64.getDecoder().decode(rs.getString("recovery_salt"));
                        String wrappedRec = rs.getString("wrapped_dek_recovery");
                        String kdfParams = rs.getString("kdf_params");

                        byte[] recKek = VaultCrypto.deriveKey(recoveryCode.toCharArray(), recSalt, kdfParams);
                        byte[] dek;
                        try {
                            dek = VaultCrypto.unwrapDek(wrappedRec, recKek);
                        } catch (AEADBadTagException bad) {
                            Arrays.fill(recKek, (byte) 0);
                            System.out.println("Recovery failed.");
                            return;
                        } finally {
                            Arrays.fill(recKek, (byte) 0);
                        }

                        // Re-wrap DEK under a new master KEK.
                        byte[] newSalt = VaultCrypto.randomSalt();
                        byte[] newKek  = VaultCrypto.deriveKey(newPwd, newSalt, VaultCrypto.DEFAULT_KDF_PARAMS);
                        String newWrapped = VaultCrypto.wrapDek(dek, newKek);
                        Arrays.fill(newKek, (byte) 0);
                        Arrays.fill(dek, (byte) 0);

                        try (PreparedStatement upd = conn.prepareStatement(
                                "UPDATE users SET kdf_salt = ?, kdf_params = ?, wrapped_dek = ?, " +
                                "failed_logins = 0, locked_until = NULL WHERE id = ?")) {
                            upd.setString(1, Base64.getEncoder().encodeToString(newSalt));
                            upd.setString(2, VaultCrypto.DEFAULT_KDF_PARAMS);
                            upd.setString(3, newWrapped);
                            upd.setInt(4, id);
                            upd.executeUpdate();
                        }
                        System.out.println("Master password reset. You may now log in with the new password.");
                    }
                }
            }
        } catch (SQLException e) {
            LOG.log(Level.WARNING, "DB error during recovery", e);
            System.out.println("Recovery failed, please try again later.");
        } finally {
            Arrays.fill(newPwd, '\0');
        }
    }

    // ===================================================================
    //  Vault item operations  (require an open Session)
    // ===================================================================

    public static void inputAndSavePassword(Scanner scan, Session session) {
        System.out.print("Enter application/service name: ");
        String service = scan.nextLine().trim();
        System.out.print("Enter username for this service: ");
        String serviceUsername = scan.nextLine().trim();
        char[] pwdChars = readPasswordChars(scan, "Enter password: ");
        String password = new String(pwdChars);
        System.out.print("Enter optional notes: ");
        String notes = scan.nextLine();

        try {
            saveItem(session, service, serviceUsername, password, notes);
        } finally {
            Arrays.fill(pwdChars, '\0');
        }
    }

    public static void saveGeneratedPassword(Scanner scan, Session session, String password) {
        System.out.print("Enter application/service name: ");
        String service = scan.nextLine().trim();
        System.out.print("Enter username for this service: ");
        String serviceUsername = scan.nextLine().trim();
        System.out.print("Enter optional notes: ");
        String notes = scan.nextLine();
        saveItem(session, service, serviceUsername, password, notes);
    }

    private static void saveItem(Session session, String service, String serviceUsername,
                                 String password, String notes) {
        byte[] dek = session.dek();
        String sql = "INSERT INTO vault_items " +
                     "(user_id, service_name_hmac, service_username_hmac, " +
                     " service_name_enc, service_username_enc, encrypted_password, notes_enc) " +
                     "VALUES (?, ?, ?, ?, ?, ?, ?)";
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt   (1, session.userId());
            stmt.setString(2, Cryptography.blindIndex(service));
            stmt.setString(3, Cryptography.blindIndex(serviceUsername));
            stmt.setString(4, VaultCrypto.encrypt(service, dek));
            stmt.setString(5, VaultCrypto.encrypt(serviceUsername, dek));
            stmt.setString(6, VaultCrypto.encrypt(password, dek));
            stmt.setString(7, VaultCrypto.encrypt(notes, dek));
            stmt.executeUpdate();
            System.out.println("Password saved for service: " + service);
        } catch (SQLException e) {
            LOG.log(Level.WARNING, "DB error saving vault item", e);
            System.out.println("Could not save password.");
        }
    }

    public static void getMyPassword(Scanner scan, Session session) {
        // Defense in depth: re-confirm master password before disclosing.
        char[] confirm = readPasswordChars(scan, "Enter your master password to confirm: ");
        try {
            if (!verifyCurrentMasterPassword(session, confirm)) {
                System.out.println("Wrong password.");
                return;
            }
        } finally {
            Arrays.fill(confirm, '\0');
        }

        System.out.println("Do you want to get 'one' password or 'all' your passwords?");
        String userInput = scan.nextLine().trim().toLowerCase(Locale.ROOT);
        switch (userInput) {
            case "one" -> getOnePassword(scan, session);
            case "all" -> getAllPasswords(session);
            default -> System.out.println("Invalid option. Please enter 'one' or 'all'.");
        }
    }

    /** Verify the current master password by re-deriving the KEK and unwrapping. */
    private static boolean verifyCurrentMasterPassword(Session session, char[] candidate) {
        String sql = "SELECT kdf_salt, kdf_params, wrapped_dek FROM users WHERE id = ?";
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, session.userId());
            try (ResultSet rs = stmt.executeQuery()) {
                if (!rs.next()) return false;
                byte[] salt = Base64.getDecoder().decode(rs.getString("kdf_salt"));
                String params = rs.getString("kdf_params");
                String wrapped = rs.getString("wrapped_dek");
                byte[] kek = VaultCrypto.deriveKey(candidate, salt, params);
                try {
                    byte[] dek = VaultCrypto.unwrapDek(wrapped, kek);
                    Arrays.fill(dek, (byte) 0);
                    return true;
                } catch (AEADBadTagException bad) {
                    return false;
                } finally {
                    Arrays.fill(kek, (byte) 0);
                }
            }
        } catch (SQLException e) {
            LOG.log(Level.WARNING, "DB error verifying master password", e);
            return false;
        }
    }

    private enum SearchBy {
        SERVICE("service_name_hmac"),
        USERNAME("service_username_hmac");
        final String column;
        SearchBy(String c) { this.column = c; }
    }

    private static void getOnePassword(Scanner scan, Session session) {
        System.out.println("Search by 'service' or 'username'?");
        String option = scan.nextLine().trim().toLowerCase(Locale.ROOT);
        SearchBy by = switch (option) {
            case "service"  -> SearchBy.SERVICE;
            case "username" -> SearchBy.USERNAME;
            default         -> null;
        };
        if (by == null) {
            System.out.println("Invalid option. Please enter 'service' or 'username'.");
            return;
        }
        System.out.print("Enter search value: ");
        String input = scan.nextLine().trim().toLowerCase(Locale.ROOT);

        String sql = "SELECT service_name_enc, service_username_enc, encrypted_password, notes_enc " +
                     "FROM vault_items WHERE user_id = ? AND " + by.column + " = ?";

        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt   (1, session.userId());
            stmt.setString(2, Cryptography.blindIndex(input));
            try (ResultSet rs = stmt.executeQuery()) {
                boolean any = false;
                byte[] dek = session.dek();
                while (rs.next()) {
                    any = true;
                    System.out.println("_____________________");
                    System.out.println("Service  : " + VaultCrypto.decrypt(rs.getString("service_name_enc"), dek));
                    System.out.println("Username : " + VaultCrypto.decrypt(rs.getString("service_username_enc"), dek));
                    System.out.println("Password : " + VaultCrypto.decrypt(rs.getString("encrypted_password"), dek));
                    System.out.println("Notes    : " + VaultCrypto.decrypt(rs.getString("notes_enc"), dek));
                }
                if (!any) System.out.println("No results found.");
            }
        } catch (SQLException e) {
            LOG.log(Level.WARNING, "DB error retrieving vault item", e);
            System.out.println("Could not retrieve password.");
        }
    }

    private static void getAllPasswords(Session session) {
        String sql = "SELECT service_name_enc, service_username_enc, encrypted_password, notes_enc " +
                     "FROM vault_items WHERE user_id = ?";
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, session.userId());
            try (ResultSet rs = stmt.executeQuery()) {
                boolean any = false;
                byte[] dek = session.dek();
                while (rs.next()) {
                    any = true;
                    System.out.println("_____________________");
                    System.out.println("Service  : " + VaultCrypto.decrypt(rs.getString("service_name_enc"), dek));
                    System.out.println("Username : " + VaultCrypto.decrypt(rs.getString("service_username_enc"), dek));
                    System.out.println("Password : " + VaultCrypto.decrypt(rs.getString("encrypted_password"), dek));
                    System.out.println("Notes    : " + VaultCrypto.decrypt(rs.getString("notes_enc"), dek));
                }
                if (!any) System.out.println("No passwords found.");
            }
        } catch (SQLException e) {
            LOG.log(Level.WARNING, "DB error listing vault items", e);
            System.out.println("Could not list passwords.");
        }
    }

    public static void changePassword(Scanner scan, Session session) {
        System.out.print("Enter application/service: ");
        String service = scan.nextLine().trim().toLowerCase(Locale.ROOT);
        char[] newPwdChars = readPasswordChars(scan, "Enter the new password for this service: ");
        try {
            String newEnc = VaultCrypto.encrypt(new String(newPwdChars), session.dek());
            try (Connection conn = getConnection();
                 PreparedStatement stmt = conn.prepareStatement(
                         "UPDATE vault_items SET encrypted_password = ? " +
                         "WHERE user_id = ? AND service_name_hmac = ?")) {
                stmt.setString(1, newEnc);
                stmt.setInt   (2, session.userId());
                stmt.setString(3, Cryptography.blindIndex(service));
                int rows = stmt.executeUpdate();
                System.out.println(rows > 0
                        ? "Password updated successfully."
                        : "No password found for that service.");
            } catch (SQLException e) {
                LOG.log(Level.WARNING, "DB error during change", e);
                System.out.println("Could not change password.");
            }
        } finally {
            Arrays.fill(newPwdChars, '\0');
        }
    }

    public static void deleteMyPassword(Scanner scan, Session session) {
        System.out.print("Enter application/service to delete: ");
        String service = scan.nextLine().trim().toLowerCase(Locale.ROOT);
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(
                     "DELETE FROM vault_items WHERE user_id = ? AND service_name_hmac = ?")) {
            stmt.setInt   (1, session.userId());
            stmt.setString(2, Cryptography.blindIndex(service));
            int rows = stmt.executeUpdate();
            System.out.println(rows > 0
                    ? "Password for service '" + service + "' deleted."
                    : "No password found for that service.");
        } catch (SQLException e) {
            LOG.log(Level.WARNING, "DB error during delete", e);
            System.out.println("Could not delete password.");
        }
    }

    // ===================================================================
    //  Helpers
    // ===================================================================

    /** Reads a password without echo when a console is attached; falls back to Scanner. */
    public static char[] readPasswordChars(Scanner scan, String prompt) {
        Console c = System.console();
        if (c != null && c.isTerminal()) {
            char[] p = c.readPassword(prompt);
            return (p == null) ? new char[0] : p;
        }
        System.out.print(prompt);
        return scan.nextLine().toCharArray();
    }

    private static char[] readMatchingPassword(Scanner scan) {
        while (true) {
            char[] a = readPasswordChars(scan, "Enter your password: ");
            char[] b = readPasswordChars(scan, "Confirm your password: ");
            boolean match = Arrays.equals(a, b);
            Arrays.fill(b, '\0');
            if (!match) {
                Arrays.fill(a, '\0');
                System.out.println("Passwords do not match. Try again.");
                continue;
            }
            if (a.length < 12) {
                Arrays.fill(a, '\0');
                System.out.println("Password must be at least 12 characters.");
                continue;
            }
            // Optional HIBP check (network — best effort).
            int pwned = HaveIBeenPwn.checkPassword(new String(a));
            if (pwned > 0) {
                Arrays.fill(a, '\0');
                System.out.println("That password appears in known breaches (" + pwned + " hits). Choose another.");
                continue;
            }
            return a;
        }
    }

    // ---------- private POJO ----------

    private static final class UserRow {
        int id;
        byte[] kdfSalt;
        String kdfParams;
        String wrappedDek;
        String totpSecretEnc;
        long lastTotpStep;
        int failedLogins;
        boolean locked; // evaluated by MySQL against NOW(), same clock that set locked_until
    }
}
