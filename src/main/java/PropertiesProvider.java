import java.io.InputStream;
import java.util.Properties;

public final class PropertiesProvider {
    public static final Properties PROPS = new Properties();
    private PropertiesProvider() {}

    static {
        try (InputStream input = PropertiesProvider.class.getClassLoader()
                .getResourceAsStream("Password.properties")) {
            if (input == null) {
                throw new IllegalStateException(
                        "Password.properties not found on classpath. " +
                        "Copy Password.properties.example to Password.properties and fill it in.");
            }
            PROPS.load(input);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load Password.properties", e);
        }

        requireNonBlank("host");
        requireNonBlank("db_name");
        requireNonBlank("port");
        // pwd may legitimately be empty (local MySQL with no password).
        // blind_index_key may be empty on first run; Cryptography will generate one and exit.
    }

    private static void requireNonBlank(String key) {
        String v = PROPS.getProperty(key);
        if (v == null || v.isBlank()) {
            throw new IllegalStateException("Missing required property: " + key);
        }
    }
}
