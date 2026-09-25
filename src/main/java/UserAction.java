public enum UserAction {
    LOGIN("1"),
    CREATE("2"),
    RESET("3"),
    VALIDATE("validate"),
    GENERATE("generate"),
    SAVE("save"),
    RETRIEVE("retrieve"),
    CHANGE("change"),
    DELETE("delete"),
    LOGOUT("logout"),
    QUIT("quit"),
    MENU("menu"),
    TRY_AGAIN("try again"),
    PWNED("have i been pwned");

    private final String input;

    UserAction(String input) { this.input = input; }

    public static UserAction fromInput(String input) {
        if (input == null) return null;
        String trimmed = input.trim();
        for (UserAction a : values()) {
            if (a.input.equalsIgnoreCase(trimmed)) return a;
        }
        return null;
    }
}
