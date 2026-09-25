# Password Manager (Java CLI)

A command-line password manager written in Java with a MySQL backend. It was built as a
learning project in applied cryptography and secure application design.

> **Disclaimer:** This is an educational project. It has not been independently audited, so
> don't use it as your only store for real credentials.

## Features

- **Envelope encryption.** Your master password is run through **Argon2id** to derive a key-encryption key (KEK).
  The KEK unwraps a random per-user **data-encryption key (DEK)**, and every vault field is encrypted
  with **AES-256-GCM** under the DEK. The master password is never stored anywhere.
- **Two-factor authentication (TOTP).** It works with Google Authenticator, Microsoft Authenticator, Authy and similar apps.
  The QR code is rendered locally, so the TOTP secret never leaves your machine. The app also rejects reused codes (replay protection).
- **Recovery code.** You get a one-time code when you create an account. It can re-wrap the DEK if you forget your master password.
- **Have I Been Pwned check.** The app checks passwords against known breaches using the k-anonymity range API,
  so only the first 5 characters of the SHA-1 hash are sent over the network.
- **Password generator** using `SecureRandom`.
- **Password validation** with a 12-character minimum, a breach check and a breach count.
- **Brute-force protection.** An account is locked for 15 minutes after 5 failed logins.
- **Searchable encryption.** Service names and usernames are stored encrypted. Lookups use an
  HMAC-SHA256 "blind index", so the database never sees plaintext.

```
master password ──Argon2id──▶ KEK ──AES-GCM unwrap──▶ DEK ──▶ vault items, TOTP secret, username
recovery code   ──Argon2id──▶ recovery KEK ──unwrap──▶ DEK
```

## Requirements

- **JDK 23** or newer
- **Maven** 3.9 or newer (IntelliJ IDEA's bundled Maven works too)
- **MySQL 8.0** running on `localhost`
- An authenticator app on your phone
- Internet access for the Have I Been Pwned check (optional; the app still works without it)

## Setup

### 1. Get the code

```bash
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>
```

You can also use **Code → Download ZIP** on GitHub.

### 2. Create the database

> ⚠️ `setup.sql` **drops and recreates** the `password_manager` database.

**Windows:** double-click `setup.bat`. It finds `mysql.exe`, asks for your MySQL credentials and runs `setup.sql`.

**macOS / Linux:**

```bash
mysql -u root -p < setup.sql
```

### 3. Configure

Copy the example config:

```bash
cp src/main/resources/Password.properties.example src/main/resources/Password.properties
```

Then fill it in:

| Key               | Value                                                                  |
|-------------------|------------------------------------------------------------------------|
| `host`            | Your MySQL **username** (for example `root`). The app always connects to `localhost`. |
| `db_name`         | `password_manager`                                                     |
| `port`            | `3306`                                                                 |
| `pwd`             | Your MySQL password                                                    |
| `blind_index_key` | Leave empty on the first run (see below)                               |

On the first run the app generates a `blind_index_key`, prints it and exits. Paste the printed value into
`Password.properties`, rebuild and run the app again.

> Keep `blind_index_key` secret, and **never change it after accounts exist**. If it changes, existing users and
> vault items can no longer be found.

`Password.properties` is listed in `.gitignore`, so never commit it.

### 4. Build and run

```bash
mvn package
java -jar target/PasswordManager-jar-with-dependencies.jar
```

In IntelliJ IDEA, open the folder as a Maven project and run `Main`.

> Maven copies `Password.properties` into the built jar, so **don't share a jar you built yourself**,
> because it contains your database password. Rebuild after every change to `Password.properties`.

## Usage

```
1: Log into your password manager account
2: Create a password manager account
3: Reset master password (with recovery code)
```

1. **Create an account.** Choose a username and a master password of at least 12 characters.
   - Write down the **recovery code**. It's shown only once.
   - Scan the **QR code** with your authenticator app. The image is deleted when the app exits.
2. **Log in** with your username, master password and 6-digit 2FA code.
3. From the menu, choose one of these:

| Command             | What it does                                                   |
|---------------------|----------------------------------------------------------------|
| `validate`          | Checks a password's length and breach status, then offers to save it |
| `generate`          | Generates a random password                                    |
| `save`              | Saves a password for a service                                 |
| `retrieve`          | Shows one or all saved passwords (asks for the master password again) |
| `change`            | Updates the password for a service                             |
| `delete`            | Deletes the password for a service                             |
| `have i been pwned` | Checks any password against known breaches                     |
| `logout` / `quit`   | Logs out or exits (the key is wiped from memory)               |

## Project structure

```
src/main/java/
├── Main.java               Entry point
├── Program.java            CLI menus
├── PasswordDB.java         Accounts, login, recovery, vault operations
├── VaultCrypto.java        Argon2id key derivation, AES-GCM, DEK wrapping
├── Cryptography.java       HMAC blind index
├── TwoFa.java              TOTP verification and QR code
├── HaveIBeenPwn.java       HIBP range API client
├── PasswordValidator.java  Password validation and generation
├── Session.java            In-memory session (holds the DEK)
├── PropertiesProvider.java Loads Password.properties
└── UserAction.java         Menu commands
setup.sql                   Database schema
setup.bat                   Windows database setup script
```

## License

[MIT](LICENSE)
