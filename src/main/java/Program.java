import java.util.Scanner;

public final class Program {

    private Program() {}

    public static void run() {
        try (Scanner scan = new Scanner(System.in)) {
            outer:
            while (true) {
                System.out.println("=====================================================");
                System.out.println("1: Log into your password manager account");
                System.out.println("2: Create a password manager account");
                System.out.println("3: Reset master password (with recovery code)");
                System.out.println("Type 'quit' to exit.");
                System.out.print("Choose: ");
                String line = scan.nextLine();
                UserAction a = UserAction.fromInput(line);
                if (a == null) { System.out.println("Invalid input."); continue; }

                switch (a) {
                    case LOGIN -> {
                        Session session = PasswordDB.login(scan);
                        if (session != null) {
                            try { menu(scan, session); }
                            finally { session.destroy(); }
                        }
                    }
                    case CREATE -> PasswordDB.createUser(scan);
                    case RESET  -> PasswordDB.resetMasterPasswordWithRecoveryCode(scan);
                    case QUIT   -> { System.out.println("Bye!"); break outer; }
                    default     -> System.out.println("Invalid option for this step.");
                }
            }
        }
    }

    private static void menu(Scanner scan, Session session) {
        while (true) {
            printMenuOptions();
            UserAction action = UserAction.fromInput(scan.nextLine());
            if (action == null) { System.out.println("Invalid input."); continue; }

            switch (action) {
                case VALIDATE -> PasswordValidator.validatePassword(scan, session);
                case GENERATE -> PasswordValidator.generatePassword(scan, session);
                case SAVE     -> PasswordDB.inputAndSavePassword(scan, session);
                case RETRIEVE -> PasswordDB.getMyPassword(scan, session);
                case CHANGE   -> PasswordDB.changePassword(scan, session);
                case DELETE   -> PasswordDB.deleteMyPassword(scan, session);
                case PWNED    -> HaveIBeenPwn.checkPasswordPwned(scan);
                case LOGOUT   -> { System.out.println("Logged out."); return; }
                case QUIT     -> { System.out.println("Bye!"); session.destroy(); System.exit(0); }
                default       -> { System.out.println("Invalid menu option."); continue; }
            }

            System.out.println("_____________________");
            System.out.println("Return to menu, log out, or quit? (menu / logout / quit)");
            UserAction next = UserAction.fromInput(scan.nextLine());
            if (next == UserAction.LOGOUT) { System.out.println("Logged out."); return; }
            if (next == UserAction.QUIT)   { System.out.println("Bye!"); session.destroy(); System.exit(0); }
            // anything else → loop back to menu
        }
    }

    private static void printMenuOptions() {
        System.out.println("_____________________");
        System.out.println("Choose an option:");
        System.out.println("- Validate");
        System.out.println("- Generate");
        System.out.println("- Save");
        System.out.println("- Retrieve");
        System.out.println("- Change");
        System.out.println("- Delete");
        System.out.println("- Have I Been Pwned");
        System.out.println("- Logout");
        System.out.println("- Quit");
        System.out.println("_____________________");
        System.out.print("Enter your choice: ");
    }
}
