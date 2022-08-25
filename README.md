# Denc
Directory encryption with AES-GCM

## Overview
DEnc or denc is a simple python program to use AES-GCM to encrypt and decrypt all contents of a directory including any other directory inside it
The key and nonce size decide whether its AES256, AES192, AES128.

## Usage
#### Encrypt a directory
python denc.py -e [path]

#### Decrypt a directory
python denc.py -e [path]

#### Using a custome key
python denc.py -e/-d [path] -k/--key [key]
