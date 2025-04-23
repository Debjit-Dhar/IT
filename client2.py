import socket
import threading
import os
from tkinter import Tk, Toplevel, Text, Entry, Button, Scrollbar, filedialog, messagebox, Label, END
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

        self.file_button = Button(root, text="Send File", command=self.send_file)
        self.file_button.pack()

        #self.view_button = Button(root, text="View Files", command=self.view_files)
        #self.view_button.pack()

        self.client_socket = client_socket
        self.cipher = cipher
        self.username = username

        threading.Thread(target=self.receive_messages, daemon=True).start()

    def send_message(self):
        """Send a text message."""
        message = self.message_entry.get().strip()
        if message:
            try:
                self.client_socket.send(self.cipher.encrypt(message.encode()))
                self.message_entry.delete(0, END)
            except:
                messagebox.showerror("Error", "Failed to send message!")
        else:
            messagebox.showwarning("Warning", "Message cannot be empty!")

    def send_file(self):
        """Send a file to another client."""
        filepath = filedialog.askopenfilename()
        if not filepath:
            return  # User canceled file selection

        recipient = self.message_entry.get().strip()
        if not recipient:
            messagebox.showwarning("Warning", "Enter recipient's name before sending a file.")
            return

        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)

        try:
            # Notify server about file transfer
            self.client_socket.send(f"FILE:{recipient}".encode())  # Unencrypted metadata for identification
            self.client_socket.send(f"{filename}:{filesize}".encode())  # Send filename and size info

            # Send the actual file in chunks
            with open(filepath, "rb") as file:
                while chunk := file.read(4096):
                    self.client_socket.send(chunk)

            self.chat_display.config(state="normal")
            self.chat_display.insert(END, f"📁 File '{filename}' sent to {recipient}.\n")
            self.chat_display.config(state="disabled")
            self.chat_display.see(END)
        except Exception as e:
            messagebox.showerror("Error", f"❌ File failed to send! Error: {e}")

    def receive_messages(self):
        """Receive messages from the server."""
        while True:
            try:
                encrypted_message = self.client_socket.recv(1024)
                message = self.cipher.decrypt(encrypted_message).decode()

                if message.startswith("FILE_RECEIVED:"):
                    filename = message.split(":")[1]
                    self.chat_display.config(state="normal")
                    self.chat_display.insert(END, f"New file received: {filename}\n")
                    self.chat_display.config(state="disabled")
                else:
                    self.chat_display.config(state="normal")
                    self.chat_display.insert(END, f"{message}\n")
                    self.chat_display.config(state="disabled")

                self.chat_display.see(END)
            except:
                break

    def view_files(self):
        """View received files in the client's dedicated directory."""
        base_dir = os.path.join(os.getcwd(), "Received_Files")
        user_folder = os.path.join(base_dir, self.username)

        if not os.path.exists(user_folder):
            messagebox.showinfo("No Files", "You have not received any files yet.")
            return

        files = os.listdir(user_folder)
        if files:
            file_list = "\n".join(files)
            messagebox.showinfo("Received Files", f"📂 Your received files:\n{file_list}")
        else:
            messagebox.showinfo("No Files", "No files received yet.")


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
        """Connect to the chat server."""
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((HOST, PORT))
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


if __name__ == "__main__":
    root = Tk()
    login = LoginWindow(root)
    login.connect_to_server()
    root.mainloop()

