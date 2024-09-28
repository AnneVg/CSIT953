import socket
import hashlib
from py_ecc.secp256k1.secp256k1 import multiply

from utils import send_data, receive_data, generate_keys, aes_encrypt, aes_decrypt, get_local_ip

# Generate server's key pair (private and public keys)
SK, PK = generate_keys("server")


def get_dh_key(client_socket):
    # Prepare the data dictionary to send (server's name and public key)
    data = {
        "name": "Server",
        "pk": PK
    }

    # Send the server's public key and other information to the client
    send_data(client_socket, data)

    # Receive client's data (client's name and public key)
    client_data = receive_data(client_socket)
    client_name, client_pk = client_data['name'], client_data['pk']

    # Perform Diffie-Hellman key exchange to compute the shared secret
    #todo: compute k via DH protocol
    k, _ = multiply(client_pk, SK)
    shared_key = hashlib.sha256(str(k).encode("utf-8")).digest()
    return client_name, client_pk, shared_key


def start_server(host='127.0.0.1', port=8080):
    """
    Start a TCP server to handle secure communication with clients.
    The server uses Diffie-Hellman (DH) key exchange for shared key generation
    and AES for encrypted messaging.

    Args:
        host (str): The server's IP address (default is '127.0.0.1').
        port (int): The port number to listen on (default is 12345).
    """

    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind the server's IP and port
    server_socket.bind((host, port))
    # Start listening for incoming connections (max 5 pending connections)
    server_socket.listen(5)
    print(f"Server listening on {host}:{port}")

    while True:
        # Accept a new client connection
        client_socket, client_address = server_socket.accept()
        print(f"Connection established with {client_address}")
        # Perform key exchange and get the shared key
        client_name, client_pk, shared_key = get_dh_key(client_socket)
        print(f"Name: {client_name}\nPublic Key: {client_pk}\nDH Key: {shared_key.hex()}")

        while True:
            sc_msg = receive_data(client_socket)
            if not sc_msg:
                break  # Connection closed or no data received

            # Decrypt the received message using the shared key
            s_msg = aes_decrypt(sc_msg, shared_key)
            print(f">>[{client_name}]:\nCiphertext: {sc_msg}\nPlaintext: {s_msg}")

            msg = input("Your message ('!Q' for quit): ")
            if msg == "!Q":     # If server wants to quit, close the connection
                client_socket.close()
                server_socket.close()
                return

            # Send the encrypted message to the client
            c_msg = aes_encrypt(msg, shared_key)
            send_data(client_socket, c_msg)

if __name__ == '__main__':
    # Start the server when script is executed
    ip = get_local_ip()
    start_server(host=ip)
