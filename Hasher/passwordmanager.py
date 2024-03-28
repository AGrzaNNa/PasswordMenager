import sqlite3
import hashlib
import secrets


class PasswordManager:
    """
    A simple password manager that securely stores passwords.
    """
    def __init__(self, db_name='passwords.db'):
        """
        Initializes the PasswordManager with a SQLite database connection.
        Args:
            db_name (str): Name of the SQLite database.
        """
        self.conn = sqlite3.connect(db_name)
        self.c = self.conn.cursor()
        self.create_passwords_table()

    def create_passwords_table(self):
        """
        Creates a table to store hashed passwords along with their salts in the database.
        """
        self.c.execute('''CREATE TABLE IF NOT EXISTS HashedPass
                        (id INTEGER PRIMARY KEY AUTOINCREMENT, final_password TEXT, salt TEXT)''')
        self.conn.commit()

    def _hash_password(self, password, salt):
        """
        Hashes the given password using PBKDF2-HMAC algorithm.

        Args:
            password (str): Password to be hashed.
            salt (bytes): Salt used in hashing.

        Returns:
            str: Hashed password.
        """
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return key.hex()

    def store_password(self, password):
        """
        Hashes the given password, stores it in the database along with its salt.

        Args:
            password (str): Password to be hashed and stored.
        """
        salt = secrets.token_bytes(16)
        final_password = self._hash_password(password, salt)

        self.c.execute("INSERT INTO HashedPass (final_password, salt) VALUES (?, ?)", (final_password, salt))
        self.conn.commit()

    def verify_password(self, user_id, password):
        """
        Verifies if the provided password matches the stored hashed password for the given user id.

        Args:
            user_id (int): User ID whose password is to be verified.
            password (str): Password to be verified.

        Returns:
            bool: True if password matches, False otherwise.
        """
        self.c.execute("SELECT final_password, salt FROM HashedPass WHERE id=?", (user_id,))
        result = self.c.fetchone()

        if result:
            stored_password_hash, salt = result[0], result[1]
            input_password_hash = self._hash_password(password, salt)

            return input_password_hash == stored_password_hash
        else:
            return False

    def close_connection(self):
        """
        Closes the SQLite database connection.
        """
        self.conn.close()



if __name__ == "__main__":
    db_name = 'passwords.db'
    pm = PasswordManager(db_name)

    ps1 = input('Input password: ')
    ps2 = input('Confirm password: ')

    if ps1 == ps2:
        pm.store_password(ps1)
        print("Password stored successfully.")
    else:
        print("Passwords do not match. Please try again.")

    print("All tests passed.")
