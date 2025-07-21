from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import bcrypt


app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed for sessions

# Mail and Serializer setup (move above route definitions)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'       # your Gmail
app.config['MAIL_PASSWORD'] = 'your-app-password'          # Gmail app password
mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            firstname TEXT,
            lastname TEXT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Drop the old users table (run once, then remove)
# def drop_users_table():
#     conn = sqlite3.connect('users.db')
#     c = conn.cursor()
#     c.execute("DROP TABLE IF EXISTS users")
#     conn.commit()
#     conn.close()

# drop_users_table()

# Ensure admin user exists
def ensure_admin():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email=?", ("admin@admin.com",))
    if not c.fetchone():
        firstname = "Admin"
        lastname = "admin"
        email = "admin@admin.com"
        password = b"admin@1234"
        hashed_pw = bcrypt.hashpw(password, bcrypt.gensalt())
        c.execute("INSERT INTO users (firstname, lastname, email, password) VALUES (?, ?, ?, ?)",
                  (firstname, lastname, email, hashed_pw))
        conn.commit()
    conn.close()

init_db()
ensure_admin()

# --- Routes ---

@app.route("/", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"].encode('utf-8')

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email=?", (email,))
        user = c.fetchone()
        conn.close()

        if user and bcrypt.checkpw(password, user[4]):
            session["user"] = email
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid email or password."
    return render_template("login.html", error=error)

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        firstname = request.form["firstname"]
        lastname = request.form["lastname"]
        email = request.form["email"]
        password = request.form["password"]
        verifypassword = request.form["verifypassword"]

        if password != verifypassword:
            error = "Passwords do not match."
            return render_template("register.html", error=error)

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            # Add columns for firstname, lastname, email if not present in your DB schema
            c.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    firstname TEXT,
                    lastname TEXT,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                )
            """)
            c.execute("INSERT INTO users (firstname, lastname, email, password) VALUES (?, ?, ?, ?)",
                      (firstname, lastname, email, hashed_pw))
            conn.commit()
            conn.close()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            error = "Email already exists."
    return render_template("register.html", error=error)

@app.route("/confirm/<token>")
def confirm_email(token):
    try:
        username = s.loads(token, salt='email-confirm', max_age=3600)  # 1 hour expiry
    except SignatureExpired:
        return "<h3>Link expired.</h3>"
    except BadSignature:
        return "<h3>Invalid token.</h3>"

    return f"<h2>{username} has been verified successfully!</h2>"


@app.route("/dashboard")
def dashboard():
    if "user" in session:
        if session["user"] == "admin@admin.com":
            # Show all users as a table
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute("SELECT id, firstname, lastname, email, password FROM users")
            users = c.fetchall()
            conn.close()
            table_rows = ''
            for u in users:
                # Don't allow admin to delete or edit themselves
                if u[3] == "admin@admin.com":
                    actions = "<td></td><td></td>"
                else:
                    actions = f"<td><a href='/edit_user/{u[0]}'>Edit</a></td>" \
                              f"<td><a href='/delete_user/{u[0]}' onclick=\"return confirm('Are you sure you want to delete this user?');\">Delete</a></td>"
                table_rows += f"<tr><td>{u[1]}</td><td>{u[2]}</td><td>{u[3]}</td><td>{u[4]}</td>{actions}</tr>"
            user_table = f"""
                <table border='1' cellpadding='5'>
                    <tr><th>First Name</th><th>Last Name</th><th>Email</th><th>Password Hash</th><th>Edit</th><th>Delete</th></tr>
                    {table_rows}
                </table>
            """
            return f"<h2>Welcome, admin!</h2><h3>Registered Users:</h3>{user_table}<p><a href='/logout'>Logout</a></p>"
@app.route("/delete_user/<int:user_id>")
def delete_user(user_id):
    if "user" not in session or session["user"] != "admin@admin.com":
        return redirect(url_for("login"))
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    # Prevent deleting admin
    c.execute("SELECT email FROM users WHERE id=?", (user_id,))
    user = c.fetchone()
    if user and user[0] != "admin@admin.com":
        c.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
    conn.close()
    return redirect(url_for("dashboard"))

@app.route("/edit_user/<int:user_id>", methods=["GET", "POST"])
def edit_user(user_id):
    if "user" not in session or session["user"] != "admin@admin.com":
        return redirect(url_for("login"))
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    if request.method == "POST":
        firstname = request.form["firstname"]
        lastname = request.form["lastname"]
        email = request.form["email"]
        password = request.form["password"]
        # Don't allow editing admin user
        c.execute("SELECT email FROM users WHERE id=?", (user_id,))
        user = c.fetchone()
        if user and user[0] == "admin@admin.com":
            conn.close()
            return "<h3>Cannot edit admin user.</h3><a href='/dashboard'>Back</a>"
        # If password is not empty, update it (hash it), else keep old
        if password:
            hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            c.execute("UPDATE users SET firstname=?, lastname=?, email=?, password=? WHERE id=?",
                      (firstname, lastname, email, hashed_pw, user_id))
        else:
            c.execute("UPDATE users SET firstname=?, lastname=?, email=? WHERE id=?",
                      (firstname, lastname, email, user_id))
        conn.commit()
        conn.close()
        return redirect(url_for("dashboard"))
    else:
        c.execute("SELECT firstname, lastname, email FROM users WHERE id=?", (user_id,))
        user = c.fetchone()
        conn.close()
        if not user:
            return "<h3>User not found.</h3><a href='/dashboard'>Back</a>"
        # Simple inline form
        return f'''
            <h2>Edit User</h2>
            <form method="post">
                <label>First Name: <input type="text" name="firstname" value="{user[0]}" required></label><br>
                <label>Last Name: <input type="text" name="lastname" value="{user[1]}" required></label><br>
                <label>Email: <input type="email" name="email" value="{user[2]}" required></label><br>
                <label>New Password (leave blank to keep unchanged): <input type="password" name="password"></label><br>
                <input type="submit" value="Update">
            </form>
            <a href='/dashboard'>Cancel</a>
        '''

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
