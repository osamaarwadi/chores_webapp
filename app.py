from flask import Flask, render_template, request, flash, session, redirect, url_for
from flask_login import login_user, login_required, logout_user, current_user
from cs50 import SQL
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import timedelta
from helpers import is_logged_in

app = Flask(__name__)
app.secret_key = "12320j34fg240i"
app.permanent_session_lifetime = timedelta(minutes=10)

db = SQL("sqlite:///database.db")
db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, username TEXT NOT NULL, hash TEXT NOT NULL, credits INTEGER DEFAULT 0)")
db.execute("CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, username TEXT NOT NULL, hash TEXT NOT NULL)")
db.execute("CREATE TABLE IF NOT EXISTS chores (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, chore TEXT NOT NULL, notes TEXT, credits INTEGER DEFAULT 0, user_id INTEGER, FOREIGN KEY (user_id) REFERENCES users(id))")
db.execute("CREATE TABLE IF NOT EXISTS rewards (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, reward TEXT NOT NULL, notes TEXT, cost INTEGER NOT NULL, user_id INTEGER, FOREIGN KEY (user_id) REFERENCES users(id))")

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':  # Only fetch chores on GET requests
        credits = 0
        if ("user_id" in session):
            row = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
            user = row[0]["username"]
            credits = row[0]["credits"]
        elif ("admin_id" in session):
            row = db.execute("SELECT * FROM admins WHERE id = ?", session["admin_id"])
            user = row[0]["username"]
        else:
            user = "anon (not signed in)"
        rows = db.execute("SELECT chores.*, users.username FROM chores LEFT JOIN users ON chores.user_id = users.id")
        return render_template("index.html", credits = credits, user = user, chores = rows)

    if request.method == 'POST':
        if ("admin_id" in session):
            if 'delete_id' in request.form:
                id = request.form['delete_id']
                db.execute("DELETE FROM chores WHERE id = ?", id)
                row = db.execute("SELECT * FROM admins WHERE id = ?", session["admin_id"])
                flash("chore deleted")
            elif 'complete_id' in request.form:
                id = request.form['complete_id']
                row = db.execute("SELECT * FROM chores WHERE id = ?", id)
                credits = row[0]["credits"]
                user_id = row[0]["user_id"]
                db.execute("DELETE FROM chores WHERE id = ?", id)
                db.execute("UPDATE users SET credits = credits + ? WHERE id = ?", credits, user_id)
                row = db.execute("SELECT * FROM admins WHERE id = ?", session["admin_id"])
                flash("chore completion confirmed")
        elif ("user_id" in session):
            id = request.form['claim_id']
            db.execute("UPDATE chores SET user_id = ? WHERE id = ?", session["user_id"], id)
            row = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
            flash("chore claimed")
        user = row[0]["username"]
        rows = db.execute("SELECT chores.*, users.username FROM chores LEFT JOIN users ON chores.user_id = users.id")
        return redirect('/')

@app.route('/sign-up-admin', methods=['GET', 'POST'])
def sign_up_admin():
    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password1")
        password2 = request.form.get("password2")
        duplicates = db.execute("SELECT * FROM admins WHERE username = ?", username)
        if (
            len(duplicates) == 0
            and username
            and len(password) > 0
            and password == password2
        ):
            db.execute(
                "INSERT INTO admins (username, hash) VALUES (?, ?)",
                username,
                generate_password_hash(password),
            )
            rows = db.execute("SELECT * FROM admins WHERE username = ?", username)
            session["admin_id"] = rows[0]["id"]
            return redirect("/")
        else:
            flash("username and/or password are invalid.")
    if is_logged_in(session):
        return redirect("/")
    else:
        return render_template("sign-up-admin.html")

@app.route('/login-admin', methods=['GET', 'POST'])
def login_admin():
    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password")
        row = db.execute("SELECT * FROM admins WHERE username = ?", username)
        if len(row) == 0:
            flash("invalid username")
        elif not check_password_hash(row[0]["hash"], request.form.get("password")):
            flash("incorrect password")
        else:
            session["admin_id"] = row[0]["id"]
            flash("login successful")
            return redirect("/")
    if is_logged_in(session):
        return redirect("/")
    else:
        return render_template("login-admin.html")

@app.route('/sign-up-user', methods=['GET', 'POST'])
def sign_up_user():
    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password1")
        password2 = request.form.get("password2")
        duplicates = db.execute("SELECT * FROM users WHERE username = ?", username)
        if (
            len(duplicates) == 0
            and username
            and len(password) > 0
            and password == password2
        ):
            db.execute(
                "INSERT INTO users (username, hash) VALUES (?, ?)",
                username,
                generate_password_hash(password),
            )
            rows = db.execute("SELECT * FROM users WHERE username = ?", username)
            session["user_id"] = rows[0]["id"]
            return redirect("/")
        else:
            flash("username and/or password are invalid.")
    if is_logged_in(session):
        return redirect("/")
    else:
        return render_template("sign-up-user.html")

@app.route('/login-user', methods=['GET', 'POST'])
def login_user():
    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password")
        row = db.execute("SELECT * FROM users WHERE username = ?", username)
        if len(row) == 0:
            flash("invalid username")
        elif not check_password_hash(row[0]["hash"], request.form.get("password")):
            flash("incorrect password")
        else:
            session["user_id"] = row[0]["id"]
            flash("login successful")
            return redirect("/")
    if is_logged_in(session):
        return redirect("/")
    else:
        return render_template("login-user.html")

@app.route('/add-chore', methods=['GET', 'POST'])
def add_chore():
    if request.method == 'POST':
        if not (request.form.get("chore") and request.form.get("credits")):
            flash("invalid chore or credits field(s).")
        else:
            chore = request.form.get("chore")
            notes = request.form.get("notes")
            credits = request.form.get("credits")
            db.execute("INSERT INTO chores (chore, notes, credits) VALUES (?, ?, ?)", chore, notes, credits)
            flash("chore added successfully")
    if "admin_id" in session:
        return render_template("add-chore.html")
    else:
        return redirect("/")

@app.route('/add-reward', methods=['GET', 'POST'])
def add_reward():
    if request.method == 'POST':
        if not (request.form.get("reward") and request.form.get("cost")):
            flash("invalid reward or cost field(s).")
        else:
            reward = request.form.get("reward")
            notes = request.form.get("notes")
            cost = request.form.get("cost")
            db.execute("INSERT INTO rewards (reward, notes, cost) VALUES (?, ?, ?)", reward, notes, cost)
            flash("reward added successfully")
    if "admin_id" in session:
        return render_template("add-reward.html")
    else:
        return redirect("/")

@app.route('/store', methods=['GET', 'POST'])
def store():
    if request.method == 'GET':  # Only fetch chores on GET requests
        rows = db.execute("SELECT rewards.*, users.username FROM rewards LEFT JOIN users ON rewards.user_id = users.id")
        return render_template("store.html", rewards = rows)
    if request.method == 'POST':
        if ("admin_id" in session):
            if 'delete_id' in request.form:
                id = request.form['delete_id']
                db.execute("DELETE FROM rewards WHERE id = ?", id)
                flash("reward deleted")
            if 'complete_id' in request.form:
                id = request.form['complete_id']
                db.execute("DELETE FROM rewards WHERE id = ?", id)
                flash("reward granted")
        if ("user_id" in session):
            if 'claim_id' in request.form:                
                id = request.form['claim_id']
                user_id = session['user_id']
                row = db.execute("SELECT * FROM rewards WHERE id = ?", id)
                cost = row[0]['cost']
                row = db.execute("SELECT * FROM users WHERE id = ?", user_id)
                credits = row[0]['credits']
                if credits < cost:
                    flash(f"reward claim failed. insufficient credits.")
                    pass
                else:
                    db.execute("UPDATE users SET credits = credits - ? WHERE id = ?", cost, user_id)
                    db.execute("UPDATE rewards SET user_id = ? WHERE id = ?", session["user_id"], id)
                    row = db.execute("SELECT credits FROM users WHERE id = ?", user_id)
                    credits = row[0]['credits']
                    flash(f"reward claimed. new credit balance: {credits}")
        rows = db.execute("SELECT rewards.*, users.username FROM rewards LEFT JOIN users ON rewards.user_id = users.id")
        return redirect(url_for('store'))

@app.route('/logout')
def logout():
    session.pop("user_id", None)
    session.pop("admin_id", None)
    return redirect("/")

if __name__ == "__main__":
  app.run()
