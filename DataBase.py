import sqlite3
import hashlib
import secrets


def create_passwords_table():
    """
    Creates a table to store hashed passwords along with their salts in the database.
    """
    c.execute('''CREATE TABLE IF NOT EXISTS HashedPass
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, final_password TEXT, salt TEXT)''')


def store_password(password):
    """
    Hashes the given password, stores it in the database along with its salt.

    Args:
        password (str): Password to be hashed and stored.
    """
    salt = secrets.token_hex(16)
    salted_password = password + salt

    password_hash = hashlib.sha224(salted_password.encode()).hexdigest()
    second_hash = hashlib.sha256(password_hash.encode()).hexdigest()
    final_password = hashlib.sha384(second_hash.encode()).hexdigest()

    c.execute("INSERT INTO HashedPass (final_password, salt) VALUES (?, ?)", (final_password, salt))
    c.commit()


def verify_password(user_id, password):
    """
    Verifies if the provided password matches the stored hashed password for the given user id.

    Args:
        user_id (int): User ID whose password is to be verified.
        password (str): Password to be verified.
    """
    c.execute("SELECT final_password, salt FROM HashedPass WHERE id=?", (user_id,))
    result = c.fetchone()

    if result:
        stored_password_hash, salt = result[0], result[1]
        salted_password = password + salt

        input_password_hash = hashlib.sha224(salted_password.encode()).hexdigest()
        second_hash = hashlib.sha256(input_password_hash.encode()).hexdigest()
        final_password = hashlib.sha384(second_hash.encode()).hexdigest()

        if final_password == stored_password_hash:
            print("Password is correct.")
        else:
            print("Password is incorrect.")
    else:
        print("Given user id does not exist.")


if __name__ == "__main__":
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()

    verify_password(1, 'admin')

    ps1 = input('Input password: ')
    ps2 = input('Confirm password: ')

    if ps1 == ps2:
        create_passwords_table()
        store_password(ps1)
        print("Password stored successfully.")
    else:
        print("Passwords do not match. Please try again.")
