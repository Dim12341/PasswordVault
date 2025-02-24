import tkinter as tk
from tkinter import messagebox
import socket
import json
import functools

# Global variable to track the theme (light/dark)
current_theme = "light"


def send_request(data):
    """Send request to the server and receive the response."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.settimeout(10)  # Timeout after 10 seconds
            client_socket.connect(('127.0.0.1', 5000))  # Using localhost (127.0.0.1) and the server port 50000
            client_socket.send(json.dumps(data).encode('utf-8'))
            response = client_socket.recv(1024).decode('utf-8')
            return json.loads(response)
    except (socket.timeout, ConnectionRefusedError) as e:
        messagebox.showerror("Connection Error",
                             "Could not connect to the server. Please make sure the server is running.")
        print(f"Connection error: {e}")
        return None
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred: {e}")
        print(f"Unexpected error: {e}")
        return None




def toggle_dark_mode():
    """Toggles between light and dark modes."""
    global current_theme
    if current_theme == "light":
        current_theme = "dark"
        window.config(bg="black")
        label_username.config(bg="black", fg="white")
        label_password.config(bg="black", fg="white")
        signup_text.config(fg="blue")  # Keep signup link blue
        login_button.config(bg="grey", fg="black")
    else:
        current_theme = "light"
        window.config(bg="white")
        label_username.config(bg="white", fg="black")
        label_password.config(bg="white", fg="black")
        signup_text.config(fg="blue")  # Keep signup link blue
        login_button.config(bg="lightgrey", fg="black")

    apply_theme()


def apply_theme():
    """Applies the theme to all components."""
    if current_theme == "dark":
        window.config(bg="black")
        label_username.config(bg="black", fg="white")
        label_password.config(bg="black", fg="white")
        signup_text.config(fg="blue")  # Ensure the signup link is blue
        login_button.config(bg="grey", fg="black")
    else:
        window.config(bg="white")
        label_username.config(bg="white", fg="black")
        label_password.config(bg="white", fg="black")
        signup_text.config(fg="blue")  # Ensure the signup link is blue
        login_button.config(bg="lightgrey", fg="black")


def login(event=None):
    """Handles user login."""
    username = entry_username.get()
    password = entry_password.get()

    if not username or not password:
        messagebox.showwarning("Input Error", "Please fill all fields")
        return

    response = send_request({"command": "login", "username": username, "password": password})
    if response and response.get("status") == "success":
        show_management_window(username)  # Pass the username to management window
    else:
        messagebox.showerror("Login Failed", response.get("message", "Invalid username or password"))


def show_management_window(username):
    """Shows the window for password management after successful login."""
    management_window = tk.Tk()
    management_window.title(f"Password Management - {username}")

    tk.Button(management_window, text="View Passwords", command=lambda: show_passwords_window(username)).pack(pady=10)
    tk.Button(management_window, text="Add New Password", command=lambda: add_new_password_window(username)).pack(pady=10)

    management_window.mainloop()


def show_passwords_window(username):
    """Displays the window showing stored passwords."""
    passwords_window = tk.Tk()
    passwords_window.title(f"Your Saved Passwords - {username}")


    response = send_request({"command": "get_passwords", "username": username})
    if response and response.get("status") == "success":
        user_passwords = response["passwords"]

        # Dictionary to keep track of password visibility for each website
        password_visibility = {}

        def toggle_password_visibility(website, password_label):
            """Toggles the visibility of the password for a specific website."""
            current_text = password_label.cget("text")
            if current_text == "*" * len(current_text):
                password_label.config(text=user_passwords[website])
            else:
                password_label.config(text="*" * len(user_passwords[website]))

        def remove_password(website):
            """Handles password removal after confirmation."""
            confirm = messagebox.askyesno("Confirmation",
                                          f"Are you sure you want to remove the password for {website}?")
            if confirm:
                response = send_request({
                    "command": "remove_password",
                    "username": username,
                    "website": website
                })
                if response and response.get("status") == "success":
                    messagebox.showinfo("Success", f"Password for {website} removed successfully.")
                    passwords_window.destroy()  # Close the window after removing password
                    show_passwords_window(username)  # Refresh the password list
                else:
                    messagebox.showerror("Error", f"Failed to remove password for {website}")
            else:
                messagebox.showinfo("Info", "Password removal canceled")

        for website, password in user_passwords.items():
            frame = tk.Frame(passwords_window)
            frame.pack(pady=5)

            tk.Label(frame, text=website).pack(side="left", padx=5)

            # Initially set the password to hidden (asterisks)
            hidden_password = "*" * len(password)
            password_label = tk.Label(frame, text=hidden_password)
            password_label.pack(side="left", padx=5)

            # Use functools.partial to capture the current values of website and password_label
            toggle_button = tk.Button(frame, text="Show Password",
                                      command=functools.partial(toggle_password_visibility, website, password_label))
            toggle_button.pack(side="left", padx=5)

            remove_button = tk.Button(frame, text="Remove Password",
                                      command=functools.partial(remove_password, website))
            remove_button.pack(side="left", padx=5)

    else:
        messagebox.showerror("Error", "No passwords found for this user.")
        passwords_window.destroy()




    passwords_window.mainloop()


def add_new_password_window(username):
    """Window to add a new password."""
    add_password_window = tk.Tk()
    add_password_window.title("Add New Password")

    tk.Label(add_password_window, text="Website Name:").pack(pady=5)
    entry_website = tk.Entry(add_password_window)
    entry_website.pack(pady=5)

    tk.Label(add_password_window, text="Password:").pack(pady=5)
    entry_password = tk.Entry(add_password_window, show="*")
    entry_password.pack(pady=5)

    def add_password():
        website = entry_website.get()
        password = entry_password.get()

        if not website or not password:
            messagebox.showwarning("Input Error", "Please fill all fields")
            return

        response = send_request({
            "command": "add_password",
            "username": username,
            "website": website,
            "password": password
        })
        if response and response.get("status") == "success":
            messagebox.showinfo("Password Added", "Password added successfully!")
            add_password_window.destroy()
        else:
            messagebox.showerror("Error", "Failed to add password")

    tk.Button(add_password_window, text="Add Password", command=add_password).pack(pady=10)
    add_password_window.mainloop()


def show_login_window():
    """Shows the login window."""
    global window
    window = tk.Tk()
    window.title("Login")

    # Set background color for light mode initially
    window.config(bg="white")

    # Username and Password labels and entry fields
    global label_username, label_password, entry_username, entry_password
    label_username = tk.Label(window, text="Username:", bg="white", fg="black")
    label_username.pack(pady=5)
    entry_username = tk.Entry(window)
    entry_username.pack(pady=5)

    label_password = tk.Label(window, text="Password:", bg="white", fg="black")
    label_password.pack(pady=5)
    entry_password = tk.Entry(window, show="*")
    entry_password.pack(pady=5)

    # Login Button
    global login_button
    login_button = tk.Button(window, text="Login", command=login, bg="lightgrey", fg="black")
    login_button.pack(pady=5)

    # Bind the Enter key to the login function
    window.bind('<Return>', login)

    # Sign up clickable text
    global signup_text
    signup_text = tk.Label(window, text="Don't have an account? Sign up here", fg="blue", cursor="hand2",
                           font=("Arial", 10, "underline"))
    signup_text.pack(pady=5)
    signup_text.bind("<Button-1>", open_signup)  # Bind the click event to open signup window

    # Dark Mode Toggle Button
    dark_mode_button = tk.Button(window, text="Toggle Dark Mode", command=toggle_dark_mode)
    dark_mode_button.pack(pady=5)

    window.mainloop()


def open_signup(event):
    """Opens the signup window."""
    window.destroy()
    signup_window()


def signup_window():
    """Shows the signup window."""
    signup_window = tk.Tk()
    signup_window.title("Sign Up")

    tk.Label(signup_window, text="Username:").pack(pady=5)
    entry_signup_username = tk.Entry(signup_window)
    entry_signup_username.pack(pady=5)

    tk.Label(signup_window, text="Password:").pack(pady=5)
    entry_signup_password = tk.Entry(signup_window, show="*")
    entry_signup_password.pack(pady=5)

    def signup():
        username = entry_signup_username.get()
        password = entry_signup_password.get()

        if not username or not password:
            messagebox.showwarning("Input Error", "Please fill all fields")
            return

        response = send_request({"command": "signup", "username": username, "password": password})

        # Check if the response is valid (i.e., a dictionary)
        if response is None:
            messagebox.showerror("Sign Up Failed", "No response from server. Please try again later.")
            return

        if "status" not in response:
            messagebox.showerror("Sign Up Failed", "Unexpected response format from server.")
            return

        if response.get("status") == "success":
            messagebox.showinfo("Sign Up Successful", "You can now log in.")
            signup_window.destroy()
            show_login_window()  # Go back to login screen
        else:
            # If the response contains a message (like "Username already exists")
            messagebox.showerror("Sign Up Failed", response.get("message", "Signup failed"))

    tk.Button(signup_window, text="Sign Up", command=signup).pack(pady=10)
    signup_window.mainloop()


if __name__ == "__main__":
    show_login_window()