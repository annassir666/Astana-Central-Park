import os
import sqlite3
import uuid
from functools import wraps
from flask import Flask, render_template, request, redirect, session, url_for, flash, g

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")
DB_PATH = "park.db"

SCADA_HOST = os.environ.get("SCADA_HOST", "127.0.0.1")
SCADA_PORT = os.environ.get("SCADA_PORT", "502")

admin_uuid = "8f4c2f70-6d52-4f5e-9c80-admin1337abc"  # Static UUID web-admin user

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def get_current_user():
    if "user_id" not in session:
        return None
    db = get_db()
    return db.execute(
        "SELECT * FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

@app.route("/")
def index():
    db = get_db()
    posts = db.execute("""
        SELECT p.*, u.username, u.uuid, u.is_admin FROM posts p 
        JOIN users u ON p.author_id = u.id 
        ORDER BY p.id ASC
    """).fetchall()
    # Convert sqlite3.Row objects to dictionaries
    posts = [{col: post[col] for col in post.keys()} for post in posts]
    return render_template("index.html", posts=posts, user=get_current_user())

@app.route("/post/<int:post_id>")
def post(post_id):
    db = get_db()
    post = db.execute("""
        SELECT p.*, u.username, u.uuid, u.is_admin FROM posts p 
        JOIN users u ON p.author_id = u.id 
        WHERE p.id = ?
    """, (post_id,)).fetchone()
    if not post:
        return "Post not found", 404
    # Convert sqlite3.Row to dictionary
    post = {col: post[col] for col in post.keys()}
    return render_template("post.html", post=post, user=get_current_user())

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        if not username or not password:
            flash("Username and password required")
            return redirect(url_for("register"))

        db = get_db()
        existing = db.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        if existing:
            flash("User already exists")
            return redirect(url_for("register"))

        user_uuid = str(uuid.uuid4())
        db.execute(
            "INSERT INTO users (username, password, uuid, is_admin) VALUES (?, ?, ?, 0)",
            (username, password, user_uuid)
        )
        db.commit()
        flash("Registered successfully", 'success')
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password)
        ).fetchone()

        if not user:
            # Check if username exists (information leak)
            user_exists = db.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,)
            ).fetchone()
            
            if user_exists:
                flash(f"Invalid password for {username}")
            else:
                flash("Invalid credentials")
            return redirect(url_for("login"))

        session["user_id"] = user["id"]
        session["uuid"] = user["uuid"]
        return redirect(url_for("profile"))

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/profile")
@login_required
def profile():
    requested_uuid = request.args.get("uuid", session.get("uuid"))

    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE uuid = ?",
        (requested_uuid,)
    ).fetchone()

    if not user:
        return "User not found", 404

    # Broken session logic: overwrite session with viewed profile
    session["uuid"] = user["uuid"]
    session["viewed_is_admin"] = user["is_admin"]

    return render_template("profile.html", profile_user=user, current_user=get_current_user())

@app.route("/profile/update", methods=["POST"])
@login_required
def update_profile():
    bio = request.form.get("bio", "").strip()
    
    db = get_db()
    db.execute(
        "UPDATE users SET bio = ? WHERE id = ?",
        (bio, session["user_id"])
    )
    db.commit()
    
    flash("Profile updated successfully!", "success")
    return redirect(url_for("profile"))

@app.route("/admin")
@login_required
def admin():
    # Vulnerability: trusts session value set by /profile?uuid=
    if not session.get("viewed_is_admin"):
        return "Admins only", 403

    return render_template(
        "admin.html",
        scada_host=SCADA_HOST,
        scada_port=SCADA_PORT
    )

@app.route("/scada")
@login_required
def scada():
    if not session.get("viewed_is_admin"):
        return "Admins only", 403
    return render_template(
        "scada.html",
        scada_host=SCADA_HOST,
        scada_port=SCADA_PORT
    )

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port, debug=False)
