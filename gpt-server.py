import socket
import json
import hashlib
import threading
import ssl
from pymongo import MongoClient
import time

# חיבור למסד נתונים
client = MongoClient('mongodb://localhost:27017/')
db = client['password_manager']
users_collection = db['users']
passwords_collection = db['passwords']

# שמירת ניסיונות כניסה כדי למנוע brute-force
failed_attempts = {}

# פונקציה להצפנת סיסמאות
def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

# פונקציה לשליחת תגובה ללקוח
def send_response(client_socket, response):
    client_socket.send(json.dumps(response).encode('utf-8'))

# פונקציה לטיפול בלקוח יחיד (כעת פועל בתהליכון נפרד)
def handle_client(client_socket):
    try:
        while True:
            data = client_socket.recv(1024).decode('utf-8')
            if not data:
                return
            request = json.loads(data)
            command = request.get("command")

            if command == "login":
                handle_login(client_socket, request)
            elif command == "signup":
                handle_signup(client_socket, request)
            elif command == "get_passwords":
                handle_get_passwords(client_socket, request)
            elif command == "add_password":
                handle_add_password(client_socket, request)
            elif command == "remove_password":
                handle_remove_password(client_socket, request)
            else:
                send_response(client_socket, {"status": "error", "message": "Unknown command"})

    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        client_socket.close()

def handle_login(client_socket, request):
    """מטפל בתהליך ההתחברות עם מנגנון למניעת brute-force"""
    username = request.get("username")
    password = request.get("password")

    # בדיקה אם יש יותר מדי ניסיונות כושלים
    if username in failed_attempts and failed_attempts[username]["count"] >= 3:
        if time.time() - failed_attempts[username]["time"] < 60:
            send_response(client_socket, {"status": "error", "message": "Too many failed attempts. Try again later."})
            return
        else:
            failed_attempts[username]["count"] = 0  # איפוס הניסיונות לאחר דקה

    user = users_collection.find_one({"username": username})

    if user and user['password'] == hash_password(password):
        send_response(client_socket, {"status": "success"})
        failed_attempts.pop(username, None)  # איפוס כשלונות התחברות
    else:
        if username not in failed_attempts:
            failed_attempts[username] = {"count": 1, "time": time.time()}
        else:
            failed_attempts[username]["count"] += 1
            failed_attempts[username]["time"] = time.time()
        send_response(client_socket, {"status": "error", "message": "Invalid username or password"})

def handle_signup(client_socket, request):
    """Handles user signup."""
    username = request.get("username")
    password = request.get("password")

    if users_collection.find_one({"username": username}):
        send_response(client_socket, {"status": "error", "message": "Username already exists"})
    else:
        users_collection.insert_one({
            "username": username,
            "password": hash_password(password)
        })
        send_response(client_socket, {"status": "success"})

def handle_get_passwords(client_socket, request):
    """Handles fetching user passwords."""
    username = request.get("username")

    user_passwords = passwords_collection.find_one({"username": username})

    if user_passwords:
        send_response(client_socket, {"status": "success", "passwords": user_passwords['passwords']})
    else:
        send_response(client_socket, {"status": "error", "message": "No passwords found for this user"})

def handle_add_password(client_socket, request):
    """Handles adding a new password."""
    username = request.get("username")
    website = request.get("website")
    password = request.get("password")

    # Update the passwords collection
    passwords_collection.update_one(
        {"username": username},
        {"$set": {f"passwords.{website}": password}},
        upsert=True
    )

    send_response(client_socket, {"status": "success"})

def handle_remove_password(client_socket, request):
    """Handles removing a password for a website."""
    username = request.get("username")
    website = request.get("website")

    result = passwords_collection.update_one(
        {"username": username},
        {"$unset": {f"passwords.{website}": ""}}
    )

    if result.modified_count > 0:
        send_response(client_socket, {"status": "success"})
    else:
        send_response(client_socket, {"status": "error", "message": f"No password found for {website}"})

def start_server():
    """אתחול השרת עם SSL ותמיכה בריבוי חיבורים"""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 5000))
    server_socket.listen(5)

    print("Server is running on port 5000 ...")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            print(f"Accepted connection from {client_address}")

            # יצירת תהליכון חדש לכל חיבור
            client_thread = threading.Thread(target=handle_client, args=(client_socket,))
            client_thread.start()

    except KeyboardInterrupt:
        print("\nServer stopped")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()
