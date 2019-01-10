from flask import Flask
import getpass
import pymongo
import hashlib
import random
import os
import struct
import string

from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto import Random


IV = ''.join(chr(random.randint(0, 130)) for i in range(16))
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["vault"]
users = db["users"]
records = db["accounts"]

rand_str = lambda n: ''.join([random.choice(string.ascii_lowercase) for _ in range(n)])

BASE = "AIOPERETRYHDCDCKSJ"


BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

base64pad = lambda s: s + b'=' * (4 - len(s) % 4)
base64unpad = lambda s: s.rstrip(b"=")


def encrypt_file(key, in_filename, out_filename=None, chunksize=64*1024):
    """ Encrypts a file using AES (CBC mode) with the
        given key.

        key:
            The encryption key - a string that must be
            either 16, 24 or 32 bytes long. Longer keys
            are more secure.

        in_filename:
            Name of the input file

        out_filename:
            If None, '<in_filename>.enc' will be used.

        chunksize:
            Sets the size of the chunk which the function
            uses to read and encrypt the file. Larger chunk
            sizes can be faster for some files and machines.
            chunksize must be divisible by 16.
    """
    if not out_filename:
        out_filename = in_filename + '.enc'

    iv = ''.join([chr(random.randint(0, 0xFF)) for i in range(16)])
    iv = Random.new().read(AES.block_size)
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - len(chunk) % 16)

                outfile.write(encryptor.encrypt(chunk))



def decrypt_file(key, in_filename, out_filename=None, chunksize=24*1024):
    """ Decrypts a file using AES (CBC mode) with the
        given key. Parameters are similar to encrypt_file,
        with one difference: out_filename, if not supplied
        will be in_filename without its last extension
        (i.e. if in_filename is 'aaa.zip.enc' then
        out_filename will be 'aaa.zip')
    """
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]

    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)



def encrypt(data, key):
    encryption_salt = rand_str(random.randint(10, 100))
    data_hash = hashlib.sha512(data.encode("utf-8")).hexdigest()
    key = hashlib.sha512((key + encryption_salt).encode()).hexdigest()[:32]
    iv = Random.new().read(BS)
    cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=AES.block_size * 8)
    encrypted_msg = cipher.encrypt(pad(str(data)))
    return base64unpad(b64encode(iv + encrypted_msg)), data_hash, encryption_salt


# when incorrect encryption key is used, `decrypt` will return empty string
def decrypt(record, key):
    hash = record["hash"]
    salt = record["salt"]
    metadata = record["metadata"]
    key = key + salt
    key = hashlib.sha512(key.encode()).hexdigest()[:32]
    decoded_msg = b64decode(base64pad(metadata))
    iv = decoded_msg[:BS]
    encrypted_msg = decoded_msg[BS:]
    cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=AES.block_size * 8)
    return unpad(cipher.decrypt(encrypted_msg))


print("\t\t VAULT 11")

def session(username, user_password):
    while True:
        print("1. Add Account \n 2. Show accounts \n 3. Delete Accounts \n 4. Update \n 5. Logout")

        action = input("Enter your choice:")
        while action not in ["1", "2", "3", "4", "5"]:
            print("Not a valid choice!!")
            action = input("Enter valid choice: ")

        if action == "1":

            store_name = input("Enter site name: ")

            login = input("Enter username: ")
            while login is '':
                login = input("Username is required: ")

            password = getpass.getpass("Enter password for account: ")
            confirmation = getpass.getpass("Confirm password: ")
            while password != confirmation or password == '':
                print("Passwords don't match or one of them is empty")
                password = getpass.getpass("Enter password for account: ")
                confirmation = getpass.getpass("Confirm password: ")

            enc_source = input("Enter 100 to choose your own password for these details else skip: ")
            encryption_password = user_password
            if enc_source == "100":
                encryption_password = getpass.getpass("Enter encryption password: ")

            data_string = login + BASE + password
            metadata, data_hash, salt = encrypt(data_string, encryption_password)
            data = {"site": store_name, "metadata": metadata, "hash": data_hash, "salt": salt, "username": username}
            records.insert_one(data)
            print("Account added successfully!\n")

        elif action == "2":

            user_details = list(records.find({"username": username}))
            if user_details != []:
                for i, j in enumerate(user_details):
                    print("{}. {} ---- {}".format(i + 1, j['site'], j['username']))
                record_decryption = input("Enter record no. you want to decrypt: ")
                record_selected = user_details[int(record_decryption) - 1]

                r = input("For custom password enter 1 (leave empty for default): ")
                cipher_key = user_password
                if r == "1":
                    cipher_key = getpass.getpass("Enter decryption password: ")
                print(cipher_key)
                detail = decrypt(record_selected, cipher_key)
                print(detail)
                if detail == '':
                    print("Incorrect Key!")
                    continue
                detail = detail.split(BASE.encode())
                print("{} ------- {}".format(detail[0], detail[1]))
                import time;
                time.sleep(10)
                import os;
                os.system("clear")
            else:
                print("No records found!")

        elif action == "3":

            user_details = list(records.find({"username": username}))
            print(user_details)
            if user_details == []:
                print("No records found!")
            else:
                for i, j in enumerate(user_details):
                     print("{}. {} ---- {}".format(i + 1, j['site'], j['username']))

                record_decryption = input("Enter record no. you want to decrypt: ")
                record_selected = user_details[int(record_decryption) - 1]
                records.delete_one(record_selected)
                print("record successfully deleted!")

        elif action == "4":

            user_details = list(records.find({"username": username}))
            if user_details == []:
                print("No records found!")
            else:
                for i, j in enumerate(user_details):
                    print("{}. {} --- {}".format(i + 1, j["site"], j["username"]))
                record_decryption = input("Enter record no. you want to decrypt: ")
                record_selected = user_details[int(record_decryption) - 1]

                new_record = {}
                current_password = getpass.getpass("Enter current decryption password ( leave blank for default): ")
                login = input("Enter new username(leave blank for default): ")
                new_password = getpass.getpass("Enter password for account(leave blank for default): ")
                if current_password == '':
                    current_password = user_password
                if new_password is not '':
                    confirmation = getpass.getpass("Confirm password: ")
                    while new_password != confirmation:
                        print("Passwords don't match!!")
                        new_password = getpass.getpass("Enter password for account: ")
                        confirmation = getpass.getpass("Confirm password: ")

                old_record = decrypt(record_selected, current_password)
                if old_record == b'':
                    print("Incorrect Password")
                else:
                    old_record = old_record.split(BASE.encode())
                    new_record["site"] = record_selected["site"]
                    data_string = ""
                    if login is '':
                        data_string += str(old_record[0]).rstrip("'").lstrip("b'")
                    else:
                        data_string += login
                    data_string += BASE
                    if new_password is '':
                        data_string += str(old_record[1]).rstrip("'").lstrip("b'")
                    else:
                        data_string += new_password
                    new_metadata, hash, salt = encrypt(data_string, current_password)
                    new_record["metadata"] = new_metadata
                    new_record["salt"] = salt
                    new_record["hash"] = hash
                    new_record["username"] = username
                    records.delete_one(record_selected)
                    records.insert_one(new_record)
                    del new_password, confirmation, current_password
                    print("record successfully updated!")

        elif action == "5":
            del user_password
            del username
            break


while True:
    print("1. Login (default) \n 2. Register \n 3. Encrypt a file \n 4. Decrypt a file \n 5. Exit")
    choice = input("Enter your choice: ")

    while choice not in ["1", "2", "3", ""]:
        print("Not a valid choice!!")
        choice = input("Enter valid choice: ")

    if choice == "2":

        username = input("Choose your username: ")
        while users.find_one({"username": username}) is not None:
            print("username already taken, try again!")
            username = input("Try another username: ")

        password = getpass.getpass("Enter password: ")
        confirm = getpass.getpass("Confirm password: ")
        while confirm != password:
            print("Passwords don't match")
            password = getpass.getpass("Enter password: ")
            confirm = getpass.getpass("Confirm password: ")

        salt = rand_str(random.randint(10, 100))
        secured_password = hashlib.sha512((password + salt).encode("utf-8")).hexdigest()
        users.insert_one({"username": username, "password": secured_password, "salt": salt})

        print("Account Successfully created!\n")

    elif choice == "1" or choice == "":
        username = input("Enter your username: ")
        user_password = getpass.getpass("Enter password: ")

        current_user = users.find_one({"username": username})
        if current_user is None:
            print("Username not found!!")
            continue

        calculated_pass = hashlib.sha512((user_password + current_user["salt"]).encode("utf-8")).hexdigest()
        if calculated_pass != current_user["password"]:
            print("Wrong password!")
            continue

        session(username=username, user_password=user_password)

    elif choice == "3":
        file_url = input("Enter expanded file path: ")
        file_encoder = getpass.getpass("Enter encryption password: ")
        if len(file_encoder) < 32:
            file_encoder += " "*(32 - len(file_encoder))
        elif len(file_encoder) > 32:
            file_encoder = file_encoder[:32]
        encrypt_file(key=file_encoder, in_filename=file_url)
        print("File encrypted successfully!")

    elif choice == "4":
        file_url = input("Enter expanded file path: ")
        file_encoder = getpass.getpass("Enter encryption password: ")
        if len(file_encoder) < 32:
            file_encoder += " "*(32 - len(file_encoder))
        elif len(file_encoder) > 32:
            file_encoder = file_encoder[:32]

        decrypt_file(key=file_encoder,in_filename=file_url)
        print("File decrypted successfully!")

    elif choice == "5":
        exit(0)

    print()
#
# app = Flask(__name__)
#
#
# @app.route('/')
# def hello_world():
#     return 'Hello World!'
#
#
# if __name__ == '__main__':
#     app.run()
