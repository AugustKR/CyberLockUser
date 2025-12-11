from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import jwt, datetime, os

# --- Load environment variables ---
load_dotenv()

app = Flask(__name__)
CORS(app)

# --- MongoDB Connection ---
MONGO_URI = os.getenv("MONGO_URI")
print("Loaded MONGO_URI:", MONGO_URI)

try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = client["questions"]
    users = db["users"]
    client.admin.command("ping")
    print("✅ Successfully connected to MongoDB Atlas!")
except Exception as e:
    print("❌ MongoDB connection failed:", e)

# --- JWT Secret Key ---
app.config["SECRET_KEY"] = "supersecretkey"  # Change this in production!

# --- Google User Registration ---
@app.route("/users", methods=["POST"])
def create_google_user():
    try:
        data = request.get_json(force=True)
        if not data or not data.get("google_id"):
            return jsonify({"error": "Missing google_id"}), 400

        if users.find_one({"google_id": data["google_id"]}):
            return jsonify({"message": "User already exists"}), 200

        users.insert_one(data)
        return jsonify({"message": "Google user created successfully"}), 201
    except Exception as e:
        print("❌ Error creating Google user:", e)
        return jsonify({"error": str(e)}), 500


# --- Manual User Registration ---
@app.route("/register", methods=["POST"])
def register_user():
    try:
        data = request.get_json(force=True)
        email = data.get("email")
        password = data.get("password")
        name = data.get("name")

        if not email or not password or not name:
            return jsonify({"error": "Missing name, email, or password"}), 400

        if users.find_one({"email": email}):
            return jsonify({"error": "User already exists"}), 400

        hashed_pw = generate_password_hash(password)
        users.insert_one({
            "name": name,
            "email": email,
            "password": hashed_pw,
            "created_at": datetime.datetime.utcnow()
        })

        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        print("❌ Error registering user:", e)
        return jsonify({"error": str(e)}), 500


# --- Manual User Login ---
@app.route("/login", methods=["POST"])
def login_user():
    try:
        data = request.get_json(force=True)
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"error": "Missing email or password"}), 400

        user = users.find_one({"email": email})
        if not user or not check_password_hash(user["password"], password):
            return jsonify({"error": "Invalid credentials"}), 401

        token = jwt.encode({
            "user": user["email"],
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
        }, app.config["SECRET_KEY"], algorithm="HS256")

        return jsonify({"token": token}), 200
    except Exception as e:
        print("❌ Error during login:", e)
        return jsonify({"error": str(e)}), 500


# --- Protected Example Route (requires JWT) ---
@app.route("/profile", methods=["GET"])
def profile():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"error": "Missing token"}), 401

    try:
        token = token.split(" ")[1]  # "Bearer <token>"
        decoded = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user = users.find_one({"email": decoded["user"]}, {"_id": 0, "password": 0})
        return jsonify(user), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401


# --- Get all users (for testing) ---
@app.route("/users", methods=["GET"])
def get_users():
    try:
        user_list = list(users.find({}, {"_id": 0, "password": 0}))
        return jsonify(user_list), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# --- Health Check ---
@app.route("/", methods=["GET"])
def home():
    return jsonify({"status": "running", "db_connected": bool(MONGO_URI)}), 200


if __name__ == "__main__":
    app.run(port=5001, debug=True)
