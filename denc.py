from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import hashlib
import getpass
import os
import sys
import threading

args = sys.argv

default_key = b'(\xb7c\x14\xb0`\xc5\xbe\xf0\\O~ac\xd6_a\xcc\xcc\xe6g\xdf*w\x97\xec\x92M]\xff\xf5\x95'   #32 bytes for AES256
nonce = b'\x9a\x1a\x12\x92\x10\xc6\xca=\xc4J\x15\xf5;\x9d\xfc\x17x\xf3\xe7\xf1$\x8cR\xce'   #24 Bytes for AES256

aes = AESGCM(default_key)


def read_in_chunks(inp_file, chunk_size=20480000):
    with open(inp_file, "rb") as f1:
        while True:
            chunk = f1.read(chunk_size)
            if not chunk:
                break

            yield chunk


def aes_init(key=default_key):
    aes = AESGCM(key)


def decrypt(cipher_text, auth):
    try:
        return aes.decrypt(nonce, cipher_text, auth)

    except InvalidTag:
        return "Invalid Password"


def encrypt(plain_text, auth):
    return aes.encrypt(nonce, plain_text, auth)


def dir_enc(DIR, auth):
    listFiles = os.listdir(DIR)

    for file in listFiles:
        lr = file.split(".").pop()
        if(lr != "denc"):
            file = f"/{file}"
            if os.path.isfile(f"{DIR}{file}"):
                with open(f"{DIR}{file}.denc", "wb") as write_file:
                    for chunk in read_in_chunks(f"{DIR}{file}"):
                        write_file.write(encrypt(chunk, auth))

                os.remove(f"{DIR.rstrip('/')}{file}")

            elif os.path.isdir(f"{DIR}{file}"):
                dir_enc(f"{DIR}{file}/", auth)


def dir_dec(DIR, auth):
    listFiles = os.listdir(DIR)

    for file in listFiles:
        if os.path.isfile(f"{DIR}/{file}"):
            nam = len(file.split("."))
            if file.split(".")[nam - 1] == "denc":
                file = f"/{file}"

                name = file.replace(".denc", "")

                with open(f"{DIR}/{name}", "wb") as wf:
                    for chunk in read_in_chunks(f"{DIR}{file}", 20480016):
                        wf.write(decrypt(chunk, auth))

                os.remove(f"{DIR.rstrip('/')}{file}")

        elif os.path.isdir(f"{DIR}/{file}"):
            dir_dec(f"{DIR}/{file}", auth)


if("--key" or "-k" in args):
    if("--key" in args):
        ind = args.index("--key")
        k = args[ind + 1]
        key = hashlib.sha3_256(k.encode()).digest()
        aes_init(key)

    elif("-k" in args):
        ind = args.index("-k")
        k = args[ind + 1]
        key = hashlib.sha3_256(k.encode()).digest()
        aes_init(key)

else:
    aes_init()

if(args[1] == "-e" or args[1] == "--encrypt"):
    password = getpass.getpass(
    prompt="Enter password to encrypt directory >> ").encode()
    #The auth needs to be 64 Bytes for AES256
    crypto_auth = hashlib.sha3_512(password).digest()

    enc_thread = threading.Thread(target=dir_enc, args=(args[2], crypto_auth))
    enc_thread.start()
    enc_thread.join()

    print("Directory Encrypted")

elif(args[1] == "-d" or args[1] == "--decrypt"):
    inv_pass = False
    password = getpass.getpass(
        prompt="Enter password to decrypt directory >> ").encode()
    crypto_auth = hashlib.sha3_512(password).digest()

    listFiles = os.listdir(args[2])
    for file in listFiles:
        if os.path.isfile(f"{args[2]}/{file}"):
            nam = len(file.split("."))
            if file.split(".")[nam - 1] == "denc":
                file = f"/{file}"

                with open(f"{args[2]}{file}", "rb") as file_check:
                    chunk = file_check.read(20480016)

                    if(decrypt(chunk, crypto_auth) == "Invalid Password"):
                        inv_pass = True

        if(inv_pass == True):
            break

    if(inv_pass == False):
        dec_thread = threading.Thread(
            target=dir_dec, args=(args[2], crypto_auth))
        dec_thread.start()
        dec_thread.join()

    else:
        print("\nInvalid Password\n")

    print("Directory Decrypted")
