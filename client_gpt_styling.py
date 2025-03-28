import tkinter as tk
from tkinter import messagebox
import socket
import json
import functools
from tkinter import ttk
import hashlib
import base64
from cryptography.fernet import Fernet
import qrcode
from PIL import ImageTk, Image


def encrypt_string(key: str, data: str) -> str:
    if len(key) != 32:
        key = hashlib.sha256(key.encode()).digest()
    key = base64.urlsafe_b64encode(key)
    cipher_suite = Fernet(key)
    encrypted_data = cipher_suite.encrypt(data.encode())
    encrypted_string = base64.urlsafe_b64encode(encrypted_data).decode('utf-8')
    return encrypted_string


def decrypt_string(key: str, encrypted_string: str) -> str:
    if len(key) != 32:
        key = hashlib.sha256(key.encode()).digest()
    key = base64.urlsafe_b64encode(key)
    cipher_suite = Fernet(key)
    encrypted_data = base64.urlsafe_b64decode(encrypted_string)
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    return decrypted_data.decode()


class Client:
    def __init__(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect(('127.0.0.1', 5000))
        except (socket.timeout, ConnectionRefusedError) as e:
            messagebox.showerror("Connection Error", "Could not connect to the server.")
            print(f"Connection error: {e}")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")
            print(f"Unexpected error: {e}")

    def send_request(self, data):
        try:
            self.client_socket.send(json.dumps(data).encode('utf-8'))
            response = self.client_socket.recv(1024).decode('utf-8')
            return json.loads(response)
        except Exception as e:
            print(f"Unexpected error: {e}")


class ManagementWindow(tk.Tk):
    def __init__(self, client, username):
        super().__init__()
        self.client = client
        self.title(f"Password Management - {username}")
        self.geometry("400x300")  # Set window size

        self.config(bg='#f4f4f4')  # Background color

        ttk.Button(self, text="View Passwords", command=lambda: PasswordsWindow(client, username)).pack(pady=20, fill='x')
        ttk.Button(self, text="Add New Password", command=lambda: AddPasswordWindow(client, username)).pack(pady=20, fill='x')

        self.center_window()
        self.mainloop()

    def center_window(self):
        # Center the window on the screen
        window_width = 400
        window_height = 300

        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()

        position_top = int(screen_height / 2 - window_height / 2)
        position_right = int(screen_width / 2 - window_width / 2)

        self.geometry(f'{window_width}x{window_height}+{position_right}+{position_top}')


class PasswordsWindow(tk.Tk):
    def __init__(self, client, username):
        super().__init__()
        self.client = client
        self.username = username
        self.title(f"Your Saved Passwords - {username}")
        self.geometry("500x400")

        self.config(bg='#e5e5e5')  # Background color

        self.encrypted_passwords = {}
        self.login_password = None
        self.password_var = tk.StringVar()

        response = self.client.send_request({"command": "get_passwords", "username": username})
        if response and response.get("status") == "success":
            if len(response["passwords"].keys()):
                self.encrypted_passwords = response["passwords"]
                self.populate_password_labels()
            else:
                messagebox.showerror("Error", "No passwords were found")
                self.destroy()
        else:
            messagebox.showerror("Error", "Error occurred while reading server response")
            self.destroy()

        self.center_window()
        self.mainloop()

    def center_window(self):
        window_width = 500
        window_height = 400

        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()

        position_top = int(screen_height / 2 - window_height / 2)
        position_right = int(screen_width / 2 - window_width / 2)

        self.geometry(f'{window_width}x{window_height}+{position_right}+{position_top}')

    def populate_password_labels(self):
        for website, encrypted_password in self.encrypted_passwords.items():
            self.display_password(encrypted_password, website)

    def display_password(self, password, website):
        frame = tk.Frame(self, bg='#e5e5e5')
        frame.pack(pady=5, fill='x', padx=10)

        ttk.Label(frame, text=website).pack(side="left", padx=5)

        hidden_password = "*" * 8  # Hide password initially
        password_label = ttk.Label(frame, text=hidden_password, font=("Arial", 10))
        password_label.pack(side="left", padx=5)

        toggle_button = ttk.Button(frame, text="Show Password", command=functools.partial(self.toggle_password_visibility, website, password_label))
        toggle_button.pack(side="left", padx=5)

        remove_button = ttk.Button(frame, text="Remove Password", command=functools.partial(self.remove_password, website))
        remove_button.pack(side="left", padx=5)

        qr_button = ttk.Button(frame, text="qr Password",
                                   command=functools.partial(self.qr_password, website))
        qr_button.pack(side="left", padx=5)

    def qr_password(self,website):
        if not self.password_var.get():
            AskPasswordDialog(self.client, self.password_var, self.username)
        else:
            decrypted_password = decrypt_string(self.password_var.get(),self.encrypted_passwords[website])
            QRCodeDialog(password=decrypted_password, website=website)



    def toggle_password_visibility(self, website, password_label):
        if not self.password_var.get():
            AskPasswordDialog(self.client, self.password_var, self.username)

        else:
            current_text = password_label.cget("text")
            if current_text == "*" * len(current_text):
                password_label.config(text=decrypt_string(self.password_var.get(), self.encrypted_passwords[website]))
            else:
                password_label.config(text="*" * 8)

    def remove_password(self, website):
        confirm = messagebox.askyesno("Confirmation", f"Are you sure you want to remove the password for {website}?")
        if confirm:
            response = self.client.send_request({"command": "remove_password", "username": self.username, "website": website})
            if response and response.get("status") == "success":
                messagebox.showinfo("Success", f"Password for {website} removed successfully.")
                self.encrypted_passwords.pop(website)
                if len(self.encrypted_passwords.keys()):
                    self.clear_window()
                    self.populate_password_labels()
                else:
                    self.destroy()
            else:
                messagebox.showerror("Error", f"Failed to remove password for {website}")
        else:
            messagebox.showinfo("Info", "Password removal canceled")

    def clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()

class QRCodeDialog(tk.Toplevel):
    def __init__(self, password, website):
        super().__init__()
        self.title(f"QR Code for {website}")
        self.geometry("500x500")
        frame = tk.Frame(self, bg='#e5e5e5')
        # Generate QR Code
        self.qr = qrcode.make(password)
        self.qr_image = self.qr.convert('RGB')

        # Convert the QR Code to a Tkinter-compatible image
        self.qr_image_tk = ImageTk.PhotoImage(self.qr_image)


        # Create a label to show the QR code image
        label = tk.Label(frame,image=self.qr_image_tk)
        label.pack(padx=10, pady=10)
        frame.pack(pady=5, fill='x', padx=10)
        tk.Button(self, text="Close", command=self.destroy).pack(pady=10)

class AskPasswordDialog(tk.Toplevel):
    def __init__(self, client, password_var, username):
        super().__init__()

        self.password_var = password_var
        self.username = username
        self.client = client
        self.title("Authenticate")
        self.geometry("300x150")
        self.configure(bg="#f4f4f9")

        tk.Label(self, text="Please enter your login password", bg="#f4f4f9", font=("Arial", 12)).pack(pady=10)

        self.login_password = tk.Entry(self, show="*", font=("Arial", 12))
        self.login_password.pack(pady=5, padx=20, fill="x")

        tk.Button(self, text="Authenticate", command=self.authenticate, bg="#4CAF50", fg="white", font=("Arial", 12)).pack(pady=10)

    def authenticate(self):
        login_password = self.login_password.get()
        if login_password:
            response = self.client.send_request({"command": "login", "username": self.username, "password": self.hash_password(login_password)})
            if response and response.get("status") == "success":
                self.password_var.set(login_password)
                self.destroy()
            else:
                messagebox.showerror("Wrong password", "You entered the wrong password")

    def hash_password(self, password):
        """Hashes a password using SHA-256."""
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

class AddPasswordWindow(tk.Tk):
    def __init__(self, client, username):
        super().__init__()

        self.client = client
        self.username = username
        self.title("Add New Password")
        self.geometry("400x300")
        self.config(bg='#f4f4f4')

        ttk.Label(self, text="Website Name:").pack(pady=5)
        self.entry_website = ttk.Entry(self)
        self.entry_website.pack(pady=5, fill='x', padx=10)

        ttk.Label(self, text="Password for the website:").pack(pady=5)
        self.website_password = ttk.Entry(self, show="*")
        self.website_password.pack(pady=5, fill='x', padx=10)

        ttk.Label(self, text="User password").pack(pady=5)
        self.login_password = ttk.Entry(self, show="*")
        self.login_password.pack(pady=5, fill='x', padx=10)

        ttk.Button(self, text="Add Password", command=self.add_password).pack(pady=20)

        self.center_window()
        self.mainloop()

    def center_window(self):
        window_width = 400
        window_height = 300

        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()

        position_top = int(screen_height / 2 - window_height / 2)
        position_right = int(screen_width / 2 - window_width / 2)

        self.geometry(f'{window_width}x{window_height}+{position_right}+{position_top}')

    def add_password(self):
        website = self.entry_website.get()
        website_password = self.website_password.get()
        login_password = self.login_password.get()

        if not website or not website_password or not login_password:
            messagebox.showwarning("Input Error", "Please fill all fields")
            return

        response = self.client.send_request({"command": "login", "username": self.username, "password": self.hash_password(login_password)})
        if response and response.get("status") == "success":
            encrypted_website_password = encrypt_string(login_password, website_password)
            response = self.client.send_request({
                "command": "add_password",
                "username": self.username,
                "website": website,
                "password": encrypted_website_password
            })
            if response and response.get("status") == "success":
                messagebox.showinfo("Password Added", "Password added successfully!")
                self.destroy()
            else:
                messagebox.showerror("Error", "Failed to add password")
        else:
            messagebox.showerror("Login password Wrong", "The login password you have entered is wrong")

    def hash_password(self, password):
        """Hashes a password using SHA-256."""
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

class LoginWindow(tk.Tk):
    def __init__(self, client):
        super().__init__()

        self.client = client
        self.title("Login")
        self.geometry("400x300")
        self.config(bg="#f4f4f4")

        self.label_username = ttk.Label(self, text="Username:")
        self.label_username.pack(pady=5)

        self.entry_username = ttk.Entry(self)
        self.entry_username.pack(pady=5, fill='x', padx=10)

        self.label_password = ttk.Label(self, text="Password:")
        self.label_password.pack(pady=5)

        self.entry_password = ttk.Entry(self, show="*")
        self.entry_password.pack(pady=5, fill='x', padx=10)

        ttk.Button(self, text="Login", command=self.handle_login).pack(pady=20)

        self.bind('<Return>', lambda event: self.handle_login())

        self.signup_text = ttk.Label(self, text="Don't have an account? Sign up here", foreground="blue")
        self.signup_text.pack(pady=5)
        self.signup_text.bind("<Button-1>", lambda event: SignUpWindow(self.client))

        self.center_window()
        self.mainloop()

    def center_window(self):
        window_width = 400
        window_height = 300

        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()

        position_top = int(screen_height / 2 - window_height / 2)
        position_right = int(screen_width / 2 - window_width / 2)

        self.geometry(f'{window_width}x{window_height}+{position_right}+{position_top}')

    def handle_login(self):
        username = self.entry_username.get()
        password = self.entry_password.get()

        if not username or not password:
            messagebox.showwarning("Input Error", "Please fill all fields")
            return

        response = self.client.send_request({"command": "login", "username": username, "password": self.hash_password(password)})
        if response and response.get("status") == "success":
            self.destroy()
            ManagementWindow(self.client, username)
        else:
            messagebox.showerror("Login Failed", "Failed to verify login credentials")

        # Helper function to hash passwords securely
    def hash_password(self, password):
        """Hashes a password using SHA-256."""
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

class SignUpWindow(tk.Tk):
    def __init__(self, client):
        super().__init__()

        self.client = client
        self.title("Sign Up")
        self.geometry("400x300")
        self.config(bg="#f4f4f4")

        ttk.Label(self, text="Username:").pack(pady=5)
        self.entry_signup_username = ttk.Entry(self)
        self.entry_signup_username.pack(pady=5, fill='x', padx=10)

        ttk.Label(self, text="Password:").pack(pady=5)
        self.entry_signup_password = ttk.Entry(self, show="*")
        self.entry_signup_password.pack(pady=5, fill='x', padx=10)

        ttk.Button(self, text="Sign Up", command=self.handle_signup).pack(pady=20)

        self.center_window()
        self.mainloop()

    def center_window(self):
        window_width = 400
        window_height = 300

        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()

        position_top = int(screen_height / 2 - window_height / 2)
        position_right = int(screen_width / 2 - window_width / 2)

        self.geometry(f'{window_width}x{window_height}+{position_right}+{position_top}')

    def handle_signup(self):
        username = self.entry_signup_username.get()
        password = self.entry_signup_password.get()

        if not username or not password:
            messagebox.showwarning("Input Error", "Please fill all fields")
            return

        response = self.client.send_request({"command": "signup", "username": username, "password": self.hash_password(password)})

        if response and response.get("status") == "success":
            messagebox.showinfo("Sign Up Successful", "You can now log in.")
            self.destroy()
        else:
            messagebox.showerror("Sign Up Failed", "Signup failed. Please try again.")

    def hash_password(self, password):
        """Hashes a password using SHA-256."""
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

if __name__ == "__main__":
    socket = Client()
    login_window = LoginWindow(socket)