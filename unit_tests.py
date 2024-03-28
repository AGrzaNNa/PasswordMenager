import os
import unittest
from Hasher import PasswordManager

class TestPasswordManager(unittest.TestCase):
    def setUp(self):
        self.db_name = 'test_passwords.db'
        self.pm = PasswordManager(self.db_name)

    def tearDown(self):
        self.pm.close_connection()
        os.remove(self.db_name)

    def test_store_password(self):
        ps = "TestPassword123"
        self.pm.store_password(ps)
        # Check if password is stored properly
        self.assertTrue(self.pm.verify_password(1, ps))

    def test_verify_correct_password(self):
        ps = "TestPassword123"
        self.pm.store_password(ps)
        # Verify correct password
        self.assertTrue(self.pm.verify_password(1, ps))

    def test_verify_incorrect_password(self):
        ps = "TestPassword123"
        incorrect_ps = "WrongPassword"
        self.pm.store_password(ps)
        # Verify incorrect password
        self.assertFalse(self.pm.verify_password(1, incorrect_ps))

if __name__ == '__main__':
    unittest.main()
