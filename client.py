import hashlib
import socket

from py_ecc.secp256k1.secp256k1 import multiply
from utils import receive_data, send_data, generate_keys, aes_encrypt, aes_decrypt, get_local_ip

# Generate client's key pair (private and public keys)
SK, PK = generate_keys("client")


def get_dh_key(server_socket):
    # Receive server's data (name and public key)
    server_data = receive_data(server_socket)
    server_name, server_pk = server_data['name'], server_data['pk']

    # Perform Diffie-Hellman key exchange to compute the shared secret
    #todo: compute k via DH protocol
    k, _ = multiply(server_pk, SK)
    shared_key = hashlib.sha256(str(k).encode("utf-8")).digest()

    # Send client's public key and other information back to the server
    data = {
        "name": "Client",
        "pk": PK
    }
    send_data(server_socket, data)
    return server_name, server_pk, shared_key


def start_client(host='127.0.0.1', port=8080):
    """
    Start a TCP client to communicate securely with the server.
    The client uses Diffie-Hellman (DH) key exchange for shared key generation
    and AES for encrypted messaging.

    Args:
        host (str): The server's IP address (default is '127.0.0.1').
        port (int): The port number to connect to (default is 12345).
    """

    # Create a TCP/IP socket for client connection
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Connect to the server at the given IP and port
    server_socket.connect((host, port))
    # Perform key exchange and get the shared key
    server_name, server_pk, shared_key = get_dh_key(server_socket)
    print(f"Connected to: {server_name}\nPublic Key: {server_pk}\nDH Key: {shared_key.hex()}")

    while True:
        msg = input("Your message ('!Q' for quit): ")
        if msg == "!Q":     # If user wants to quit, close the connection
            server_socket.close()
            break

        # Send the encrypted message to the server
        c_msg = aes_encrypt(msg, shared_key)
        send_data(server_socket, c_msg)

        # Receive and decrypt the response from the server
        sc_msg = receive_data(server_socket)
        s_msg = aes_decrypt(sc_msg, shared_key)
        print(f">>[{server_name}]:\nCiphertext: {sc_msg}\nPlaintext: {s_msg}")


if __name__ == "__main__":
    # Start the client when the script is executed
    ip = get_local_ip()
    start_client(host=ip)
