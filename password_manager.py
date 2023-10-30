import os
import json
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, kdf
from cryptography.hazmat.primitives.hashes import SHA256
import random
import string
import re
from datetime import datetime, timedelta
import getpass
import hmac

class PasswordManager:
    def __init__(self, master_password):
        self.master_password = master_password
        self.passwords = {}
        self.password_history = {}
        self.password_expiry = {}
        self.salt = os.urandom(16)
        self.key = self.generate_key(master_password)
        self.load_passwords()
        self.secret_2fa = base64.b64encode(os.urandom(32)).decode()

    def generate_key(self, password):
        kdf_instance = kdf.PBKDF2HMAC(
            algorithm=SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf_instance.derive(password.encode())

    def encrypt(self, plaintext):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode()

    def decrypt(self, ciphertext):
        ciphertext = base64.b64decode(ciphertext)
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(decryptor.update(ciphertext) + decryptor.finalize()) + unpadder.finalize()
        return plaintext.decode()

    def save_passwords(self):
        with open('passwords.json', 'w') as f:
            data = {
                "passwords": {site: self.encrypt(password) for site, password in self.passwords.items()},
                "password_history": {site: [self.encrypt(password) for password in history] for site, history in self.password_history.items()},
                "password_expiry": self.password_expiry,
                "salt": base64.b64encode(self.salt).decode(),
                "secret_2fa": self.secret_2fa
            }
            json.dump(data, f)

    def load_passwords(self):
        if os.path.exists('passwords.json'):
            with open('passwords.json', 'r') as f:
                data = json.load(f)
                self.salt = base64.b64decode(data.get("salt", ""))
                self.key = self.generate_key(self.master_password)  # Regenerate key after loading salt
                self.passwords = {site: self.decrypt(password) for site, password in data.get("passwords", {}).items()}
                self.password_history = {site: [self.decrypt(password) for password in history] for site, history in data.get("password_history", {}).items()}
                self.password_expiry = data.get("password_expiry", {})
                self.secret_2fa = data.get("secret_2fa", "")

    def add_password(self, site, password, expiry_days=90):
        if site in self.passwords:
            if not self.password_history.get(site):
                self.password_history[site] = []
            self.password_history[site].append(self.passwords[site])
        self.passwords[site] = password
        self.password_expiry[site] = (datetime.now() + timedelta(days=expiry_days)).strftime('%Y-%m-%d')
        self.save_passwords()

    def generate_password(self, length=12):
        if length < 8:
            print("Password length should be at least 8 characters.")
            return None
        characters = string.ascii_letters + string.digits + string.punctuation
        while True:
            password = ''.join(random.choice(characters) for i in range(length))
            if self.is_password_complex(password):
                return password
            print("Generated password does not meet complexity requirements. Generating a new one...")

    def is_password_complex(self, password):
        if (len(password) >= 8 and
            re.search(r'[a-z]', password) and
            re.search(r'[A-Z]', password) and
            re.search(r'\d', password) and
            re.search(r'\W', password)):
            return True
        return False

    def analyze_password_strength(self, password):
        if len(password) < 8:
            return "Weak"
        elif self.is_password_complex(password):
            return "Strong"
        else:
            return "Moderate"

    def get_password(self, site):
        if site in self.password_expiry and self.password_expiry[site] < datetime.now().strftime('%Y-%m-%d'):
            print(f"Warning: The password for {site} has expired. Please update it as soon as possible.")
        return self.passwords.get(site, None)

    def auto_fill(self, site):
        password = self.get_password(site)
        if password is not None:
            print(f"Auto-filling password for {site}")
            return password
        else:
            print("Password not found for this site")
            return None

    def verify_2fa(self, code):
        correct_code = hmac.new(self.secret_2fa.encode(), datetime.now().strftime('%Y-%m-%d %H').encode(), 'sha256').hexdigest()[:6]
        return hmac.compare_digest(code, correct_code)

# Example usage:
master_password = getpass.getpass("Enter your master password: ")
pm = PasswordManager(master_password)

while True:
    action = input("What would you like to do? (add/get/generate/analyze/autofill/2fa/quit): ")
    if action == 'add':
        site = input("Enter the site name: ")
        password = getpass.getpass("Enter the password: ")
        pm.add_password(site, password)
    elif action == 'get':
        site = input("Enter the site name: ")
        password = pm.get_password(site)
        if password:
            print(f"Password for {site}: {password}")
        else:
            print("Password not found.")
    elif action == 'generate':
        length = int(input("Enter the password length: "))
        password = pm.generate_password(length)
        if password:
            print(f"Generated password: {password}")
    elif action == 'analyze':
        password = getpass.getpass("Enter the password to analyze: ")
        strength = pm.analyze_password_strength(password)
        print(f"Password strength: {strength}")
    elif action == 'autofill':
        site = input("Enter the site name: ")
        pm.auto_fill(site)
    elif action == '2fa':
        code = input("Enter the 2FA code: ")
        if pm.verify_2fa(code):
            print("2FA verification successful!")
        else:
            print("2FA verification failed.")
    elif action == 'quit':
        break
    else:
        print("Invalid action. Please enter add, get, generate, analyze, autofill, 2fa, or quit.")