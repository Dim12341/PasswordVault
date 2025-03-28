import tkinter as tk
from tkinter import messagebox
import socket
import json
import functools
from tkinter import ttk
import hashlib
import base64
from cryptography.fernet import Fernet


def encrypt_string(key: str, data: str) -> str:
    # Step 1: Ensure the key is 32 bytes for Fernet
    if len(key) != 32:
        print(f"Provided key length is {len(key)} characters.")
        # Hash the key to ensure it is 32 bytes
        key = hashlib.sha256(key.encode()).digest()  # Hash the key to get a 32-byte value
        print("Using hashed key to meet the 32-byte requirement.")

    # Ensure the key is Base64 encoded (Fernet expects it this way)
    key = base64.urlsafe_b64encode(key)  # Convert to base64 format if necessary

    # Step 2: Initialize Fernet with the provided key
    cipher_suite = Fernet(key)

    # Step 3: Encrypt the data
    encrypted_data = cipher_suite.encrypt(data.encode())  # Convert the string to bytes and encrypt

    encrypted_string = base64.urlsafe_b64encode(encrypted_data).decode('utf-8')  # Convert bytes to string

    return encrypted_string


def decrypt_string(key: str, encrypted_string: str) -> str:
    # Step 1: Ensure the key is 32 bytes for Fernet
    if len(key) != 32:
        print(f"Provided key length is {len(key)} characters.")
        # Hash the key to ensure it is 32 bytes
        key = hashlib.sha256(key.encode()).digest()  # Hash the key to get a 32-byte value
        print("Using hashed key to meet the 32-byte requirement.")

    # Ensure the key is Base64 encoded (Fernet expects it this way)
    key = base64.urlsafe_b64encode(key)  # Convert to base64 format if necessary

    # Step 2: Initialize Fernet with the provided key
    cipher_suite = Fernet(key)

    # Step 3: Decode the Base64-encoded encrypted string back to bytes
    encrypted_data = base64.urlsafe_b64decode(encrypted_string)  # Decode the Base64 string back to bytes

    # Step 4: Decrypt the data
    decrypted_data = cipher_suite.decrypt(encrypted_data)  # Decrypt the bytes

    # Convert the decrypted bytes back to a string
    return decrypted_data.decode()

class Client:
    def __init__(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self. client_socket.connect(('127.0.0.1', 5000))  # Using localhost (127.0.0.1) and the server port 50000
        except (socket.timeout, ConnectionRefusedError) as e:
            messagebox.showerror("Connection Error",
                                 "Could not connect to the server. Please make sure the server is running.")
            print(f"Connection error: {e}")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")
            print(f"Unexpected error: {e}")

    def send_request(self,data):
        try:
            self.client_socket.send(json.dumps(data).encode('utf-8'))
            response = self.client_socket.recv(1024).decode('utf-8')
            return json.loads(response)
        except Exception as e:
            print(f"Unexpected error: {e}")




class ManagementWindow(tk.Tk):
    def __init__(self,client,username):
        super().__init__()

        self.client = client

        self.title(f"Password Management - {username}")

        tk.Button(self, text="View Passwords", command=lambda: PasswordsWindow(client,username)).pack(
            pady=10)
        tk.Button(self, text="Add New Password", command=lambda: AddPasswordWindow(client,username)).pack(
            pady=10)

        self.mainloop()


class AskPasswordDialog(tk.Toplevel):
    def __init__(self,client, password_var,username):
        super().__init__()

        self.password_var = password_var
        self.username = username
        self.client = client
        self.title("Authenticate")
        tk.Label(self, text="Please enter your login password").pack(pady=5)
        self.login_password = tk.Entry(self)
        self.login_password.pack(pady=5)

        tk.Button(self, text="Authenticate", command=self.authenticate).pack(pady=10)

    def authenticate(self):
        login_password = self.login_password.get()
        if login_password:
            response = self.client.send_request({"command": "login", "username": self.username, "password": login_password})
            if response and response.get("status") == "success":
                self.password_var.set(login_password)
                self.destroy()
            else:
                messagebox.showerror("Wrong password", "You entered the wrong password")




class PasswordsWindow(tk.Tk):
    def __init__(self,client,username):
        super().__init__()

        self.client = client

        self.username=username
        self.title(f"Your Saved Passwords - {username}")

        #need to get user passwords from client
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
            messagebox.showerror("Error", "error occurred while reading server response")
            self.destroy()

        self.mainloop()



    def populate_password_labels(self):
        for website, encrypted_password in self.encrypted_passwords.items():
            self.display_password(encrypted_password, website)

    def display_password(self,password,website):
        frame = tk.Frame(self)
        frame.pack(pady=5)

        tk.Label(frame, text=website).pack(side="left", padx=5)

        # Initially set the password to hidden (asterisks)
        hidden_password = "*" * 8 #len(password)
        password_label = tk.Label(frame, text=hidden_password)
        password_label.pack(side="left", padx=5)

        # Use functools.partial to capture the current values of website and password_label
        toggle_button = tk.Button(frame, text="Show Password",
                                  command=functools.partial(self.toggle_password_visibility, website, password_label))
        toggle_button.pack(side="left", padx=5)

        remove_button = tk.Button(frame, text="Remove Password",
                                  command=functools.partial(self.remove_password, website))
        remove_button.pack(side="left", padx=5)

    def toggle_password_visibility(self,website, password_label):
        """Toggles the visibility of the password for a specific website."""
        if not self.password_var.get():
            AskPasswordDialog(self.client,self.password_var,self.username)

        else:
            current_text = password_label.cget("text")
            if current_text == "*" * len(current_text):
                password_label.config(text=decrypt_string(self.password_var.get(),self.encrypted_passwords[website]))
            else:
                password_label.config(text="*" * 8)#len(self.user_passwords[website]))


    def remove_password(self,website):
        """Handles password removal after confirmation."""
        confirm = messagebox.askyesno("Confirmation",
                                      f"Are you sure you want to remove the password for {website}?")
        if confirm:
            response = self.client.send_request({
                "command": "remove_password",
                "username": self.username,
                "website": website
            })
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
        # Destroy all widgets inside the window
        for widget in self.winfo_children():
            widget.destroy()


class AddPasswordWindow(tk.Tk):
    def __init__(self,client,username):
        super().__init__()

        self.client = client
        self.username= username

        self.title("Add New Password")

        tk.Label(self, text="Website Name:").pack(pady=5)
        self.entry_website = tk.Entry(self)
        self.entry_website.pack(pady=5)

        tk.Label(self, text="Password for the website:").pack(pady=5)
        self.website_password = tk.Entry(self, show="*")
        self.website_password.pack(pady=5)

        tk.Label(self, text="User password").pack(pady=5)
        self.login_password = tk.Entry(self, show="*")
        self.login_password.pack(pady=5)

        tk.Button(self, text="Add Password", command=self.add_password).pack(pady=10)
        self.mainloop()

    def add_password(self):
        website = self.entry_website.get()
        website_password = self.website_password.get()
        login_password = self.login_password.get()

        if not website or not website_password or not login_password:
            messagebox.showwarning("Input Error", "Please fill all fields")
            return

        response = self.client.send_request({"command": "login", "username": self.username, "password": login_password})
        if response and response.get("status") == "success":
            encrypted_website_password = encrypt_string(login_password,website_password)
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
            messagebox.showerror("Login password Wrong", "The login password you have entered in wrong")



class LoginWindow(tk.Tk):
    def __init__(self,client):
        super().__init__()
        self.client = client
        self.title("Login")
        # Set background color for light mode initially
        self.config(bg="white")

        self.label_username = tk.Label(self, text="Username:", bg="white", fg="black")
        self.label_username.pack(pady=5)
        self.entry_username = tk.Entry(self)
        self.entry_username.pack(pady=5)

        self.label_password = tk.Label(self, text="Password:", bg="white", fg="black")
        self.label_password.pack(pady=5)
        self.entry_password = tk.Entry(self, show="*")
        self.entry_password.pack(pady=5)

        # Login Button
        self.login_button = tk.Button(self, text="Login", command=self.handle_login, bg="lightgrey", fg="black")
        self.login_button.pack(pady=5)

        # Bind the Enter key to the login function
        self.bind('<Return>',lambda event:self.handle_login())

        # Sign up clickable text
        self.signup_text = tk.Label(self, text="Don't have an account? Sign up here", fg="blue", cursor="hand2",
                               font=("Arial", 10, "underline"))
        self.signup_text.pack(pady=5)
        self.signup_text.bind("<Button-1>", lambda event: SignUpWindow(client))  # Bind the click event to open signup window

        self.mainloop()

    def handle_login(self):
        """Handles user login."""
        username = self.entry_username.get()
        password = self.entry_password.get()

        if not username or not password:
            messagebox.showwarning("Input Error", "Please fill all fields")
            return

        response = self.client.send_request({"command": "login", "username": username, "password": password})
        if response and response.get("status") == "success":
            self.destroy()
            ManagementWindow(self.client,username)  # Pass the username to management window

        else:
            messagebox.showerror("Login Failed","Failed to verify log in credentials")





class SignUpWindow(tk.Tk):
    def __init__(self,client):
        super().__init__()
        self.client=client
        self.title("Sign Up")

        tk.Label(self, text="Username:").pack(pady=5)
        self.entry_signup_username = tk.Entry(self)
        self.entry_signup_username.pack(pady=5)

        tk.Label(self, text="Password:").pack(pady=5)
        self.entry_signup_password = tk.Entry(self, show="*")
        self.entry_signup_password.pack(pady=5)

        tk.Button(self, text="Sign Up", command=self.handle_signup).pack(pady=10)
        self.mainloop()


    def handle_signup(self):
        username = self.entry_signup_username.get()
        password = self.entry_signup_password.get()

        if not username or not password:
            messagebox.showwarning("Input Error", "Please fill all fields")
            return

        response = self.client.send_request({"command": "signup", "username": username, "password": password})

        # Check if the response is valid (i.e., a dictionary)
        if response is None:
            messagebox.showerror("Sign Up Failed", "No response from server. Please try again later.")
            return

        if "status" not in response:
            messagebox.showerror("Sign Up Failed", "Unexpected response format from server.")
            return

        if response.get("status") == "success":
            messagebox.showinfo("Sign Up Successful", "You can now log in.")
            self.destroy()
        else:
            # If the response contains a message (like "Username already exists")
            messagebox.showerror("Sign Up Failed", response.get("message", "Signup failed"))



if __name__ == "__main__":
    socket = Client()
    login_window = LoginWindow(socket)