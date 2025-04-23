import socket
import threading
import sqlite3
from tkinter import Tk, Label, Button, Listbox, Entry, END, messagebox
from cryptography.fernet import Fernet
from bcrypt import hashpw, gensalt, checkpw
import os
from tkinter import Tk, Label, Button, Listbox, Entry, END, messagebox
from cryptography.fernet import Fernet
from bcrypt import hashpw, gensalt, checkpw

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
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            sender TEXT,
            recipient TEXT,
            message TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def save_message(sender, recipient, message):
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO messages (sender, recipient, message) VALUES (?, ?, ?)", (sender, recipient, message))
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


def save_file(client, sender, recipient):
    """Receive a file from the client and save it in recipient's dedicated folder."""
    
    # Receive file metadata (unencrypted)
    file_info = client.recv(1024).decode()
    filename, filesize = file_info.split(":")
    filesize = int(filesize)

    # ✅ Ensure recipient's folder exists
    base_dir = os.path.join(os.getcwd(), "Received_Files")
    recipient_folder = os.path.join(base_dir, recipient)

    if not os.path.exists(recipient_folder):  
        os.makedirs(recipient_folder)  # 🔥 Create directory if it does not exist

    filepath = os.path.join(recipient_folder, filename)

    # ✅ Receive and save the file in chunks
    with open(filepath, "wb") as file:
        remaining = filesize
        while remaining > 0:
            data = client.recv(min(4096, remaining))
            if not data:
                break
            file.write(data)
            remaining -= len(data)

    print(f"✅ File '{filename}' received from {sender} for {recipient}, saved in '{recipient_folder}'.")

    # ✅ Notify recipient if online
    if recipient in usernames:
        usernames[recipient].send(cipher.encrypt(f"FILE_RECEIVED:{filename}".encode()))


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
            usernames[username] = client
            clients[client] = username
            broadcast(cipher.encrypt(f"{username} joined the chat.".encode()))

            while True:
                encrypted_message = client.recv(1024)
                message = cipher.decrypt(encrypted_message).decode()

                if message.startswith("FILE:"):
                    recipient = message.split(":")[1]
                    save_file(client, username, recipient)
                elif ":" in message:
                    recipient, msg = message.split(":", 1)
                    broadcast(cipher.encrypt(f"{username} (to {recipient}): {msg}".encode()), recipient=recipient)
                else:
                    broadcast(cipher.encrypt(f"{username}: {message}".encode()), sender=client)
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
