import tkinter as tk
from tkinter import messagebox
import socket
import hashlib
from py_ecc.secp256k1.secp256k1 import multiply
from utils import send_data, receive_data, generate_keys, aes_encrypt, aes_decrypt, get_local_ip

def connect():
    name = entry_name.get()
    secretkey = entry_secretkey.get()
    ip = entry_ip.get()
    port = int(entry_port.get())
    
    # Display the IP and Port in the label
    label_status.config(text=f"your ip & port: {ip}:{port}")
    
    try:
        # Create a TCP/IP socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Connect to the server
        client_socket.connect((ip, port))
        
        # Generate client's key pair (private and public keys)
        SK, PK = generate_keys("client")
        
        # Prepare the data dictionary to send (client's name and public key)
        data = {
            "name": name,
            "pk": PK
        }
        
        # Send the client's public key and other information to the server
        send_data(client_socket, data)
        
        # Receive server's data (server's name and public key)
        server_data = receive_data(client_socket)
        server_name, server_pk = server_data['name'], server_data['pk']
        
        # Perform Diffie-Hellman key exchange to compute the shared secret
        k, _ = multiply(server_pk, SK)
        shared_key = hashlib.sha256(str(k).encode("utf-8")).digest()
        
        # Display the shared secret key in the GUI
        messagebox.showinfo("Connection Info", f"Connected to {server_name} with shared key: {shared_key.hex()}")
        
        # Close the connection
        client_socket.close()
        
    except Exception as e:
        messagebox.showerror("Connection Error", f"Failed to connect: {e}")

def update_secretkey_label(*args):
    secretkey = entry_secretkey.get()
    label_secretkey_display.config(text=f"Secretkey: {secretkey}")

# Create the main window
root = tk.Tk()
root.title("Connection Form")

# Create and place the widgets
tk.Label(root, text="Name:").grid(row=0, column=0, padx=10, pady=5)
entry_name = tk.Entry(root)
entry_name.grid(row=0, column=1, padx=10, pady=5)

tk.Label(root, text="Secretkey:").grid(row=1, column=0, padx=10, pady=5)
entry_secretkey = tk.Entry(root, show="*")  # Show asterisks for secret key
entry_secretkey.grid(row=1, column=1, padx=10, pady=5)

tk.Label(root, text="IP Address:").grid(row=2, column=0, padx=10, pady=5)
entry_ip = tk.Entry(root)
entry_ip.grid(row=2, column=1, padx=10, pady=5)

tk.Label(root, text="Port:").grid(row=3, column=0, padx=10, pady=5)
entry_port = tk.Entry(root)
entry_port.grid(row=3, column=1, padx=10, pady=5)

button_connect = tk.Button(root, text="Connect", command=connect)
button_connect.grid(row=4, column=0, columnspan=2, pady=10)

label_status = tk.Label(root, text="your ip & port: ")
label_status.grid(row=5, column=0, columnspan=2, pady=5)

# Start the main loop
root.mainloop()
