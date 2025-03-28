import socket
import json
import hashlib
from pymongo import MongoClient
import threading


class DB:
    # Initialize MongoDB client
    client = MongoClient('mongodb://localhost:27017/')
    db = client['password_manager']
    users_collection = db['users']
    passwords_collection = db['passwords']

    def __init__(self):
        return

    def is_user_exists(self,username):
        return self.users_collection.find_one({"username": username})

    def insert_user(self,username,password):
        self.users_collection.insert_one({
            "username": username,
            "password": password
        })

    def get_passwords(self,username):
        return self.passwords_collection.find_one({"username": username})

    def insert_password(self,username,website,website_password):
        # Update the passwords collection
        self.passwords_collection.update_one(
            {"username": username},
            {"$set": {f"passwords.{website}": website_password}},
            upsert=True
        )

    def delete_password(self,username,website):
        return self.passwords_collection.update_one(
            {"username": username},
            {"$unset": {f"passwords.{website}": ""}}
        )



class Server:

    def __init__(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('127.0.0.1', 5000))  # Using localhost (127.0.0.1) and port 50000

    def start_server(self):
        self.server_socket.listen(5)
        print("Server is running on port 50000...")
        try:
            while True:
                client_socket, client_address = self.server_socket.accept()
                print(f"Accepted connection from {client_address}")
                threading.Thread(target=self.handle_client,args=(client_socket,)).start()
        except KeyboardInterrupt:
            print("\nServer stopped")

    # Helper function to hash passwords securely
    def hash_password(self,password):
        """Hashes a password using SHA-256."""
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

    def handle_client(self,client_socket):
        """Handles communication with the client."""

        db = DB()

        try:
            while True:
                data = client_socket.recv(1024).decode('utf-8')
                if not data:
                    return
                request = json.loads(data)

                command = request.get("command")

                if command == "login":
                    self.handle_login(client_socket, request,db)
                elif command == "signup":
                    self.handle_signup(client_socket, request,db)
                elif command == "get_passwords":
                    self.handle_get_passwords(client_socket, request,db)
                elif command == "add_password":
                    self.handle_add_password(client_socket, request,db)
                elif command == "remove_password":
                    self.handle_remove_password(client_socket, request,db)
                else:
                    self.send_response(client_socket, {"status": "error", "message": "Unknown command"})

        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client_socket.close()

    def handle_login(self,client_socket, request,db):
        """Handles user login."""
        username = request.get("username")
        password = request.get("password")

        user = db.is_user_exists(username)

        if user and user['password'] == password:
            self.send_response(client_socket, {"status": "success"})
        else:
            self.send_response(client_socket, {"status": "error", "message": "Invalid username or password"})

    def handle_signup(self,client_socket, request,db):
        """Handles user signup."""
        username = request.get("username")
        password = request.get("password")

        if db.is_user_exists(username):
            self.send_response(client_socket, {"status": "error", "message": "Username already exists"})
        else:
            db.insert_user(username,password)
            self.send_response(client_socket, {"status": "success"})

    def handle_get_passwords(self,client_socket, request,db):
        """Handles fetching user passwords."""
        username = request.get("username")

        user_passwords = db.get_passwords(username)

        if user_passwords:
            self.send_response(client_socket, {"status": "success", "passwords": user_passwords['passwords']})
        else:
            self.send_response(client_socket, {"status": "error", "message": "No passwords found for this user"})

    def handle_add_password(self,client_socket, request,db):
        """Handles adding a new password."""
        username = request.get("username")
        website = request.get("website")
        password = request.get("password")

        db.insert_password(username,website,password)

        self.send_response(client_socket, {"status": "success"})

    def handle_remove_password(self,client_socket, request,db):
        """Handles removing a password for a website."""
        username = request.get("username")
        website = request.get("website")

        result = db.delete_password(username,website)

        if result.modified_count > 0:
            self.send_response(client_socket, {"status": "success"})
        else:
            self.send_response(client_socket, {"status": "error", "message": f"No password found for {website}"})

    def send_response(self,client_socket, response):
        """Sends a response back to the client."""
        client_socket.send(json.dumps(response).encode('utf-8'))

if __name__ == "__main__":
    server = Server()
    server.start_server()
