import socket
import threading
from tkinter import Tk, Toplevel, Text, Entry, Button, Scrollbar, messagebox, Label, END
from cryptography.fernet import Fernet

# Server Configuration
HOST = '127.0.0.1'
PORT = 12346


class ChatClient:
    def __init__(self, root, client_socket, cipher, username):
        self.root = root
        self.root.title("Chat Client")

        self.chat_display = Text(root, state="disabled", height=20, width=50)
        self.chat_display.pack()

        scrollbar = Scrollbar(root, command=self.chat_display.yview)
        scrollbar.pack(side="right", fill="y")
        self.chat_display["yscrollcommand"] = scrollbar.set

        self.message_entry = Entry(root)
        self.message_entry.pack()

        self.send_button = Button(root, text="Send", command=self.send_message)
        self.send_button.pack()

        self.client_socket = client_socket
        self.cipher = cipher
        self.username = username

        threading.Thread(target=self.receive_messages, daemon=True).start()

    def send_message(self):
        """Send a message."""
        message = self.message_entry.get().strip()
        if message:
            try:
                self.client_socket.send(self.cipher.encrypt(message.encode()))
                self.message_entry.delete(0, END)
            except:
                messagebox.showerror("Error", "Failed to send message!")
        else:
            messagebox.showwarning("Warning", "Message cannot be empty!")

    def receive_messages(self):
        """Receive messages."""
        while True:
            try:
                encrypted_message = self.client_socket.recv(1024)
                message = self.cipher.decrypt(encrypted_message).decode()
                self.chat_display.config(state="normal")
                self.chat_display.insert(END, f"{message}\n")
                self.chat_display.config(state="disabled")
                self.chat_display.see(END)
            except:
                break


class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Login")

        Label(root, text="Username:").pack()
        self.username_entry = Entry(root)
        self.username_entry.pack()

        Label(root, text="Password:").pack()
        self.password_entry = Entry(root, show="*")
        self.password_entry.pack()

        self.login_button = Button(root, text="Login", command=self.authenticate)
        self.login_button.pack()

        self.client_socket = None
        self.cipher = None

    def connect_to_server(self):
        """Connect to the server."""
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((HOST, PORT))

            # Receive encryption key
            key = self.client_socket.recv(1024)
            self.cipher = Fernet(key)
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {e}")
            self.root.quit()

    def authenticate(self):
        """Authenticate the user."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            messagebox.showwarning("Warning", "Both fields are required!")
            return

        try:
            self.client_socket.send(f"{username}:{password}".encode())
            response = self.client_socket.recv(1024).decode()

            if response == "INVALID":
                messagebox.showerror("Error", "Invalid credentials!")
            else:
                messagebox.showinfo("Success", "Login successful!")
                self.root.destroy()

                main_window = Tk()
                ChatClient(main_window, self.client_socket, self.cipher, username)
                main_window.mainloop()
        except Exception as e:
            messagebox.showerror("Error", f"Authentication failed: {e}")


if __name__ == "__main__":
    root = Tk()
    login = LoginWindow(root)
    login.connect_to_server()
    root.mainloop()
