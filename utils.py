import json
import os
import pickle
import socket
import struct
import random

from Crypto.Cipher import AES
from Crypto.Util import Counter
from py_ecc.secp256k1.secp256k1 import G, multiply, N


# Generate or load an existing private-public key pair for elliptic curve cryptography.
def generate_keys(filename):
    pk_name = f"{filename}.pk.json"
    sk_name = f"{filename}.sk.json"

    # If the keys already exist, load them from files
    if os.path.exists(sk_name):
        private_key = json.load(open(sk_name, "r"))
        public_key = json.load(open(pk_name, "r"))
    else:
        # Generate a new private key and corresponding public key
        private_key = random.randint(1, N - 1)
        public_key = multiply(G, private_key)

        # Save the generated keys
        json.dump(public_key, open(pk_name, 'w'))
        json.dump(private_key, open(sk_name, 'w'))

    return private_key, public_key


# Encrypt a message using AES encryption in CTR mode.
def aes_encrypt(message, key):
    if isinstance(message, str):
        message = message.encode('utf-8')

    # Initialize a 128-bit counter for CTR mode
    ctr = Counter.new(128)
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)

    # Encrypt the message
    ciphertext = aes.encrypt(message)
    return ciphertext


# Decrypt ciphertext using AES encryption in CTR mode.
def aes_decrypt(ciphertext, key):
    # Initialize a 128-bit counter for CTR mode
    ctr = Counter.new(128)
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)

    # Decrypt the ciphertext
    decrypted_message = aes.decrypt(ciphertext)
    return decrypted_message.decode('utf-8')


# Receive data from a socket until the specified length is met.
def recvall(sock, length):
    data = b''
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            return None
        data += packet
    return data


# Serialize and send data over a socket connection.
def send_data(conn, data):
    # Serialize the data using pickle
    serialized_data = pickle.dumps(data)

    # Send the length of the serialized data (4 bytes, big-endian)
    data_length = struct.pack('!I', len(serialized_data))
    conn.sendall(data_length)

    # Send the actual serialized data in chunks
    conn.sendall(serialized_data)


# Receive and deserialize data from a socket connection.
def receive_data(sock):
    # First, receive the length of the incoming data (4 bytes, big-endian)
    raw_data_length = recvall(sock, 4)
    if not raw_data_length:
        return None

    # Unpack the data length
    data_length = struct.unpack('!I', raw_data_length)[0]

    # Receive the full data based on the extracted length
    serialized_data = recvall(sock, data_length)

    # Deserialize the data using pickle
    data = pickle.loads(serialized_data)
    return data


# Get local network ip
def get_local_ip():
    return socket.gethostbyname(socket.gethostname())
