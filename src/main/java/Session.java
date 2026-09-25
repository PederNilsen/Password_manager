import java.util.Arrays;

public final class Session {
    private final int userId;
    private final String displayUsername;
    private final byte[] dek;
    private boolean destroyed;

    public Session(int userId, String displayUsername, byte[] dek) {
        this.userId = userId;
        this.displayUsername = displayUsername;
        this.dek = dek;
    }

    public int userId() { ensureLive(); return userId; }
    public String displayUsername() { ensureLive(); return displayUsername; }
    public byte[] dek() { ensureLive(); return dek; }

    public void destroy() {
        if (!destroyed) {
            Arrays.fill(dek, (byte) 0);
            destroyed = true;
        }
    }

    private void ensureLive() {
        if (destroyed) throw new IllegalStateException("Session already destroyed");
    }
}
