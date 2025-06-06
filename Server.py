# === IMPORTS ===
import socket
import json
import hashlib
from pymongo import MongoClient
import threading


# === DATABASE CLASS ===
class DB:
    # Set up MongoDB client and select the database and collections
    client = MongoClient('mongodb://localhost:27017/')
    db = client['password_manager']
    users_collection = db['users']
    passwords_collection = db['passwords']

    def __init__(self):
        return

    def is_user_exists(self, username):
        """Check if a user with the given username exists."""
        return self.users_collection.find_one({"username": username})

    def insert_user(self, username, password):
        """Insert a new user with hashed password into the database."""
        self.users_collection.insert_one({
            "username": username,
            "password": password
        })

    def get_passwords(self, username):
        """Retrieve all stored passwords for a given user."""
        return self.passwords_collection.find_one({"username": username})

    def insert_password(self, username, website, website_password):
        """
        Insert or update a password entry for a specific website under a user's account.
        If the user doesn't exist in the collection, create a new document.
        """
        self.passwords_collection.update_one(
            {"username": username},
            {"$set": {f"passwords.{website}": website_password}},
            upsert=True
        )

    def delete_password(self, username, website):
        """Delete the stored password for a specific website."""
        return self.passwords_collection.update_one(
            {"username": username},
            {"$unset": {f"passwords.{website}": ""}}
        )


# === SERVER CLASS ===
class Server:

    def __init__(self):
        # Initialize the server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('127.0.0.1', 5000))  # Bind to localhost and port 5000

    def start_server(self):
        """Start the server and listen for incoming client connections."""
        self.server_socket.listen(5)
        print("Server is running on port 5000...")
        try:
            while True:
                client_socket, client_address = self.server_socket.accept()
                print(f"Accepted connection from {client_address}")
                # Handle each client in a new thread
                threading.Thread(target=self.handle_client, args=(client_socket,)).start()
        except KeyboardInterrupt:
            print("\nServer stopped")

    def hash_password(self, password):
        """Hashes a password using SHA-256 (currently unused in logic)."""
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

    def handle_client(self, client_socket):
        """Main handler for incoming client requests."""
        db = DB()

        try:
            while True:
                data = client_socket.recv(1024).decode('utf-8')
                if not data:
                    return
                request = json.loads(data)

                command = request.get("command")

                # Dispatch the command to the appropriate handler
                if command == "login":
                    self.handle_login(client_socket, request, db)
                elif command == "signup":
                    self.handle_signup(client_socket, request, db)
                elif command == "get_passwords":
                    self.handle_get_passwords(client_socket, request, db)
                elif command == "add_password":
                    self.handle_add_password(client_socket, request, db)
                elif command == "remove_password":
                    self.handle_remove_password(client_socket, request, db)
                else:
                    self.send_response(client_socket, {"status": "error", "message": "Unknown command"})

        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client_socket.close()

    def handle_login(self, client_socket, request, db):
        """Handles login requests from clients."""
        username = request.get("username")
        password = request.get("password")

        user = db.is_user_exists(username)

        if user and user['password'] == password:
            self.send_response(client_socket, {"status": "success"})
        else:
            self.send_response(client_socket, {"status": "error", "message": "Invalid username or password"})

    def handle_signup(self, client_socket, request, db):
        """Handles signup requests from clients."""
        username = request.get("username")
        password = request.get("password")

        if db.is_user_exists(username):
            self.send_response(client_socket, {"status": "error", "message": "Username already exists"})
        else:
            db.insert_user(username, password)
            self.send_response(client_socket, {"status": "success"})

    def handle_get_passwords(self, client_socket, request, db):
        """Handles requests to retrieve all saved passwords for a user."""
        username = request.get("username")

        user_passwords = db.get_passwords(username)

        if user_passwords:
            self.send_response(client_socket, {"status": "success", "passwords": user_passwords['passwords']})
        else:
            self.send_response(client_socket, {"status": "error", "message": "No passwords found for this user"})

    def handle_add_password(self, client_socket, request, db):
        """Handles requests to add a new password for a website."""
        username = request.get("username")
        website = request.get("website")
        password = request.get("password")

        db.insert_password(username, website, password)
        self.send_response(client_socket, {"status": "success"})

    def handle_remove_password(self, client_socket, request, db):
        """Handles requests to remove a password for a specific website."""
        username = request.get("username")
        website = request.get("website")

        result = db.delete_password(username, website)

        if result.modified_count > 0:
            self.send_response(client_socket, {"status": "success"})
        else:
            self.send_response(client_socket, {"status": "error", "message": f"No password found for {website}"})

    def send_response(self, client_socket, response):
        """Sends a JSON-formatted response back to the client."""
        client_socket.send(json.dumps(response).encode('utf-8'))


# === ENTRY POINT ===
if __name__ == "__main__":
    server = Server()
    server.start_server()
