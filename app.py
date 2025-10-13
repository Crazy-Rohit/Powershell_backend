from flask import Flask, jsonify, request, session
from flask_cors import CORS
from pymongo import MongoClient
from bson import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
from flask_socketio import SocketIO
from threading import Thread
import urllib.parse

# ======================================================
# Initialization
# ======================================================
load_dotenv()
app = Flask(__name__)

# ======================================================
# Session & CORS Configuration
# ======================================================
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")
app.permanent_session_lifetime = timedelta(days=1)

APP_DOMAIN = os.getenv("APP_DOMAIN")
FRONTEND_URLS = [
    o.strip() for o in os.getenv("FRONTEND_URLS", "http://localhost:3000").split(",")
]

if APP_DOMAIN:
    app.config.update(
        SESSION_COOKIE_DOMAIN=f".{APP_DOMAIN}",
        SESSION_COOKIE_SAMESITE="None",
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
    )
else:
    app.config.update(
        SESSION_COOKIE_SAMESITE="None",
        SESSION_COOKIE_SECURE=False,
        SESSION_COOKIE_HTTPONLY=True,
    )

CORS(
    app,
    supports_credentials=True,
    resources={r"/*": {"origins": FRONTEND_URLS}},
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
)

socketio = SocketIO(app, cors_allowed_origins=FRONTEND_URLS)

# ======================================================
# MongoDB Setup
# ======================================================
mongo_uri = os.getenv("MONGO_URI")
mongo_db = os.getenv("MONGO_DB")
user_coll = os.getenv("MONGO_USER_COLLECTION")
screen_coll = os.getenv("MONGO_SCREENSHOT_COLLECTION")

client = MongoClient(mongo_uri)
db = client[mongo_db]
users = db["users"]

# ======================================================
# Helper Functions
# ======================================================
def get_user_df():
    data = list(db[user_coll].find({}, {"_id": 0})) if user_coll else []
    if not data:
        return pd.DataFrame()
    df = pd.DataFrame(data)
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df["date"] = df["timestamp"].dt.date
        df["hour"] = df["timestamp"].dt.hour
        df["day_of_week"] = df["timestamp"].dt.day_name()
    return df


def get_screenshot_df():
    data = list(db[screen_coll].find({}, {"_id": 0})) if screen_coll else []
    if not data:
        return pd.DataFrame()
    df = pd.DataFrame(data)
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df["date"] = df["timestamp"].dt.date
    return df


# ======================================================
# Authentication Routes
# ======================================================
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not username or not email or not password:
        return jsonify({"message": "All fields are required"}), 400

    if users.find_one({"email": email}):
        return jsonify({"message": "User already exists"}), 409

    hashed_password = generate_password_hash(password)
    users.insert_one(
        {
            "username": username,
            "email": email,
            "password_hash": hashed_password,
            "created_at": datetime.utcnow(),
            "last_login": None,
        }
    )
    return jsonify({"message": "User registered successfully"}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    user = users.find_one({"email": email})
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"message": "Invalid email or password"}), 401

    # ✅ Create a proper session
    session.permanent = True
    session["user"] = user["email"]
    session["user_id"] = str(user["_id"])

    users.update_one({"email": email}, {"$set": {"last_login": datetime.utcnow()}})

    # ✅ Explicitly attach cookie to response (Render/SocketIO fix)
    response = jsonify({
        "message": "Login successful",
        "username": user["username"]
    })
    app.session_interface.save_session(app, session, response)

    return response, 200


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully"}), 200


@app.route("/profile", methods=["GET"])
def profile():
    if "user" not in session:
        return jsonify({"message": "Not logged in"}), 401

    email = session["user"]
    user = users.find_one({"email": email}, {"_id": 0, "password_hash": 0})
    if not user:
        return jsonify({"message": "User not found"}), 404

    for k in ("created_at", "last_login"):
        if k in user and user[k] is not None:
            user[k] = user[k].isoformat()
    return jsonify(user), 200


@app.route("/api/profile", methods=["GET"])
def api_profile():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        doc = users.find_one({"_id": ObjectId(session["user_id"])})
    except Exception:
        return jsonify({"error": "Invalid user ID"}), 400

    if not doc:
        return jsonify({"error": "User not found"}), 404

    out = {
        "_id": str(doc.get("_id")),
        "username": doc.get("username"),
        "email": doc.get("email"),
        "created_at": doc.get("created_at").isoformat() if doc.get("created_at") else None,
        "last_login": doc.get("last_login").isoformat() if doc.get("last_login") else None,
    }
    return jsonify(out), 200


# ======================================================
# Analytics Routes
# ======================================================
@app.route("/metrics", methods=["GET"])
def metrics():
    df = get_user_df()
    df_s = get_screenshot_df()

    metrics = {
        "total_active_time": 0,
        "total_apps": 0,
        "most_used_app": "-",
        "total_screenshots": len(df_s),
        "top_category": "-",
    }

    if df.empty:
        return jsonify(metrics)

    df = df.sort_values("timestamp")
    if len(df) > 1:
        time_diff = (df["timestamp"].max() - df["timestamp"].min()).total_seconds() / 3600
        metrics["total_active_time"] = round(time_diff, 2)

    if "application" in df.columns:
        metrics["total_apps"] = df["application"].nunique()
        metrics["most_used_app"] = df["application"].mode()[0]

    if "category" in df.columns:
        metrics["top_category"] = df["category"].mode()[0]

    return jsonify(metrics)


@app.route("/analysis", methods=["GET"])
def analysis():
    df = get_user_df()
    df_s = get_screenshot_df()
    out = {}

    if df.empty:
        return jsonify(out)

    if "date" in df.columns:
        daily = df.groupby("date").size().reset_index(name="Count")
        out["activity_over_time"] = {
            "x": daily["date"].astype(str).tolist(),
            "y": daily["Count"].tolist(),
            "title": "Activity Over Time",
        }

    if "application" in df.columns:
        apps = df["application"].value_counts().head(10)
        out["top_apps"] = {
            "x": apps.index.tolist(),
            "y": apps.values.tolist(),
            "title": "Top 10 Applications",
        }

    if "category" in df.columns:
        cat = df["category"].value_counts()
        out["category_distribution"] = {
            "labels": cat.index.tolist(),
            "values": cat.values.tolist(),
            "title": "Category Distribution",
        }

    if "hour" in df.columns:
        hourly = df["hour"].value_counts().sort_index()
        out["hourly_activity"] = {
            "x": hourly.index.astype(str).tolist(),
            "y": hourly.values.tolist(),
            "title": "Hourly Activity",
        }

    if not df_s.empty and "date" in df_s.columns:
        shots = df_s.groupby("date").size().reset_index(name="Count")
        out["screenshots_over_time"] = {
            "x": shots["date"].astype(str).tolist(),
            "y": shots["Count"].tolist(),
            "title": "Screenshots Over Time",
        }

    return jsonify(out)


# ======================================================
# Table Routes ✅
# ======================================================
@app.route("/table/user_logs", methods=["GET"])
def user_table():
    df = get_user_df()
    if df.empty:
        return jsonify({"columns": [], "rows": []})
    df = df.fillna("").astype(str)
    cols = ["timestamp", "username", "application", "category", "operation", "details"]
    df = df[[c for c in cols if c in df.columns]]
    return jsonify({"columns": list(df.columns), "rows": df.head(100).to_dict(orient="records")})


@app.route("/table/screenshots", methods=["GET"])
def screenshot_table():
    df = get_screenshot_df()
    if df.empty:
        return jsonify({"columns": [], "rows": []})
    df = df.fillna("").astype(str)
    if "file_path" in df.columns:
        df = df.drop(columns=["file_path"])
    return jsonify({"columns": list(df.columns), "rows": df.head(100).to_dict(orient="records")})


# ======================================================
# Real-Time Change Stream
# ======================================================
def watch_mongo_changes():
    try:
        pipeline = [{"$match": {"operationType": {"$in": ["insert", "update", "replace"]}}}]
        with client.watch(pipeline=pipeline, full_document="updateLookup") as stream:
            print("🔁 MongoDB Change Stream is active...")
            for _ in stream:
                socketio.emit("db_update", {"message": "Database updated"})
    except Exception as e:
        print(f"[Change Stream Error] {e}")


Thread(target=watch_mongo_changes, daemon=True).start()

# ======================================================
# Diagnostics Endpoint ✅
# ======================================================
@app.route("/routes")
def list_routes():
    """List all registered routes to confirm deployment."""
    output = []
    for rule in app.url_map.iter_rules():
        methods = ','.join(rule.methods)
        line = urllib.parse.unquote(f"{rule.rule} ({methods})")
        output.append(line)
    return "<br>".join(sorted(output))


# ======================================================
# Health Check
# ======================================================
@app.route("/healthz")
def healthz():
    return jsonify({"ok": True}), 200


# ======================================================
# Run
# ======================================================
if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
