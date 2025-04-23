import socket
import threading
import sqlite3
from tkinter import Tk, Label, Button, Listbox, Entry, END, messagebox
from cryptography.fernet import Fernet
from bcrypt import hashpw, gensalt, checkpw
import os
import base64
import json
import time

UPLOADS_DIR = "uploads"
os.makedirs(UPLOADS_DIR, exist_ok=True)

def save_file(sender, recipient, filename, file_data):
    # Generate unique filename to avoid collisions
    base, ext = os.path.splitext(filename)
    unique_name = f"{base}_{int(time.time())}{ext}"
    filepath = os.path.join(UPLOADS_DIR, unique_name)
    
    with open(filepath, 'wb') as f:
        f.write(file_data)
    return filepath

# Server Configuration
HOST = '127.0.0.1'
PORT = 12346

clients = {}  # {client_socket: username}
usernames = {}  # {username: client_socket}
cipher_key = Fernet.generate_key()
cipher = Fernet(cipher_key)

def init_db():
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            sender TEXT,
            recipient TEXT,
            message TEXT,
            message_type TEXT,  -- 'text', 'file'
            file_path TEXT,     -- Path to saved file
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_message(sender, recipient, message, message_type='text', file_path=None):
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO messages (sender, recipient, message, message_type, file_path) 
        VALUES (?, ?, ?, ?, ?)
    """, (sender, recipient, message, message_type, file_path))
    conn.commit()
    conn.close()

def get_previous_chats(username):
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT sender, recipient, message, timestamp FROM messages
        WHERE sender = ? OR recipient = ?
        ORDER BY timestamp ASC
    """, (username, username))
    messages = cursor.fetchall()
    conn.close()
    return messages

def broadcast(message, recipient=None, sender=None):
    """Send a message to a specific recipient or broadcast to all clients."""
    if recipient:
        target_client = usernames.get(recipient)
        if target_client:
            try:
                target_client.send(message)
            except:
                remove_client(target_client)
    else:
        for client in clients:
            if client != sender:
                try:
                    client.send(message)
                except:
                    remove_client(client)

def authenticate_user(client):
    """Authenticate or register a user."""
    client.send("AUTH".encode())
    creds = client.recv(1024).decode().split(":")
    username, password = creds[0], creds[1]

    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    if result:
        if checkpw(password.encode(), result[0].encode()):
            return username
        else:
            client.send("INVALID".encode())
            return None
    else:
        hashed_pw = hashpw(password.encode(), gensalt()).decode()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
        conn.commit()
        return username

def handle_client(client):
    try:
        client.send(cipher_key)
        username = authenticate_user(client)

        if username:
            # Send previous chat messages
            previous_chats = get_previous_chats(username)
            for sender, recipient, message, timestamp in previous_chats:
                formatted_message = f"{sender} (to {recipient}): {message}"
                client.send(cipher.encrypt(formatted_message.encode()))

            usernames[username] = client
            clients[client] = username
            broadcast(cipher.encrypt(f"{username} joined the chat.".encode()))

            while True:
                encrypted_message = client.recv(1024)
                if not encrypted_message:
                    break

                try:
                    decrypted = cipher.decrypt(encrypted_message).decode()
                    message_data = json.loads(decrypted)

                    if message_data['type'] == 'text':
                        save_message(username, message_data['recipient'], message_data['content'])
                        broadcast(cipher.encrypt(decrypted.encode()), recipient=message_data['recipient'])
                    elif message_data['type'] == 'file':
                        file_data = base64.b64decode(message_data['content'])
                        filepath = save_file(username, message_data['recipient'], message_data['filename'], file_data)

                        save_message(username, message_data['recipient'], message_data['filename'], message_type='file', file_path=filepath)

                        notification = f"FILE:{username}:{message_data['filename']}"
                        broadcast(cipher.encrypt(notification.encode()), recipient=message_data['recipient'])
                except Exception as e:
                    print(f"Error: {e}")
                    break
        else:
            client.close()
    except:
        remove_client(client)

def remove_client(client):
    """Remove a disconnected client."""
    if client in clients:
        username = clients.pop(client)
        usernames.pop(username, None)
        broadcast(cipher.encrypt(f"{username} has left the chat.".encode()))
        client.close()

class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat Server")

        self.status_label = Label(root, text="Server is stopped.")
        self.status_label.pack()

        self.client_list = Listbox(root)
        self.client_list.pack()

        self.start_button = Button(root, text="Start Server", command=self.start_server)
        self.start_button.pack()

        self.stop_button = Button(root, text="Stop Server", command=self.stop_server, state="disabled")
        self.stop_button.pack()

        self.message_entry = Entry(root)
        self.message_entry.pack()

        self.broadcast_button = Button(root, text="Broadcast Message", command=self.broadcast_message)
        self.broadcast_button.pack()

        self.server_socket = None
        self.is_running = False

    def start_server(self):
        """Start the server."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((HOST, PORT))
        self.server_socket.listen()
        self.is_running = True

        self.status_label.config(text="Server is running...")
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")

        threading.Thread(target=self.accept_clients, daemon=True).start()

    def stop_server(self):
        """Stop the server."""
        self.is_running = False
        if self.server_socket:
            self.server_socket.close()
        self.status_label.config(text="Server is stopped.")
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")

    def accept_clients(self):
        """Accept new client connections."""
        while self.is_running:
            try:
                client, addr = self.server_socket.accept()
                self.client_list.insert(END, f"{addr}")
                threading.Thread(target=handle_client, args=(client,), daemon=True).start()
            except:
                break

    def broadcast_message(self):
        """Send a broadcast message from the server."""
        message = self.message_entry.get().strip()
        if message:
            broadcast(cipher.encrypt(f"SERVER: {message}".encode()))
            self.message_entry.delete(0, END)
        else:
            messagebox.showwarning("Warning", "Message cannot be empty!")

if __name__ == "__main__":
    init_db()
    root = Tk()
    server_gui = ServerGUI(root)
    root.mainloop()

