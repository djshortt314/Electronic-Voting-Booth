import os
import secrets
import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import json


class CLA:
    def __init__(self):
        self.validation_numbers = {}
        self.license_numbers_file = "license_numbers.txt"
        self.validation_numbers_file = "validation_numbers.txt"
        self.ctf_list_file = "ctf_validation_list.txt"
        self.key_file = "key.txt"

    def encrypt_data(self, data, key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = iv + encryptor.update(data.encode()) + encryptor.finalize()
        return base64.b64encode(encrypted_data).decode("utf-8")

    def decrypt_data(self, encrypted_data, key):
        encrypted_data = base64.b64decode(encrypted_data.encode("utf-8"))
        iv = encrypted_data[:16]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_data[16:]) + decryptor.finalize()

    def generate_validation_number(self):
        return secrets.token_hex(16)

    def validate_user(self, name, birthdate, license_number, key):
        try:
            with open(self.license_numbers_file, "a+") as file:
                file.seek(0)
                existing_license_numbers = file.readlines()
                existing_license_numbers = [line.strip() for line in existing_license_numbers]
                if license_number in existing_license_numbers:
                    return "Driver's license number has already been used."
                file.write(license_number + "\n")
        except Exception as e:
            print(f"Error writing to {self.license_numbers_file}: {e}")
            return "Error with license number processing."

        user_data = f"{name}:{birthdate}:{license_number}"
        encrypted_user_data = self.encrypt_data(user_data, key)

        validation_number = self.generate_validation_number()
        encrypted_validation_number = self.encrypt_data(validation_number, key)

        self.validation_numbers[name] = validation_number

        try:
            with open(self.validation_numbers_file, "a+") as file:
                file.write(f"{name}: {validation_number}\n")
        except Exception as e:
            print(f"Error writing to {self.validation_numbers_file}: {e}")
            return "Error with validation number processing."

        return validation_number

    def send_to_ctf(self):
        try:
            with open(self.ctf_list_file, "w") as file:
                json.dump(self.validation_numbers, file)
        except Exception as e:
            print(f"Error writing to {self.ctf_list_file}: {e}")
            return "Error sending data to CTF."

    def read_or_generate_key(self):
        try:
            if not os.path.exists(self.key_file):
                with open(self.key_file, "wb") as file:
                    key = os.urandom(32)
                    file.write(key)
            with open(self.key_file, "rb") as file:
                key = file.read()
            if len(key) != 32:
                raise ValueError("Key must be 32 bytes for AES-256 encryption.")
            return key
        except Exception as e:
            print(f"Error reading or generating key: {e}")
            return None

    def calculate_age(self, birthdate):
        birth_date = datetime.datetime.strptime(birthdate, "%m-%d-%Y")
        today = datetime.datetime.today()
        age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
        return age


if __name__ == "__main__":
    cla = CLA()

    key = cla.read_or_generate_key()
    if key is None:
        print("Failed to generate or read key.")
        exit(1)

    while True:
        first_name = input("Enter your first name: ").strip()
        last_name = input("Enter your last name: ").strip()
        license_number = input("Enter your driver's license number (max 12 characters): ").strip()

        if len(license_number) > 12:
            print("Driver's license number must not exceed 12 characters. Please try again.")
            continue

        if not first_name or not last_name or not license_number:
            print("All fields are required. Please try again.")
            continue

        while True:
            birthdate = input("Enter your birthdate (MM-DD-YYYY): ").strip()
            try:
                datetime.datetime.strptime(birthdate, "%m-%d-%Y")
                age = cla.calculate_age(birthdate)
                if age < 18:
                    print("You must be 18 or older to apply. Entry denied.")
                    exit(0)
                break
            except ValueError:
                print("Invalid birthdate format. Please enter in MM-DD-YYYY format.")

        break

    full_name = f"{first_name} {last_name}"
    validation_number = cla.validate_user(full_name, birthdate, license_number, key)
    print(f"Validation number for {full_name}: {validation_number}")

    cla.send_to_ctf()

    print(f"License numbers are stored in: {os.path.abspath(cla.license_numbers_file)}")
    print(f"Validation numbers are stored in: {os.path.abspath(cla.validation_numbers_file)}")
    print(f"Key is stored in: {os.path.abspath(cla.key_file)}")
    print(f"CTF data is stored in: {os.path.abspath(cla.ctf_list_file)}")
