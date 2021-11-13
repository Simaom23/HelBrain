import os
import sqlite3

from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import login_required, template

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure SQLite database
database = sqlite3.connect("app.db", check_same_thread=False)
db = database.cursor()


@ app.route("/", methods=["GET"])
def index():
    return redirect("/homepage")


@ app.route("/register", methods=["GET", "POST"])
def register():
    return render_template("register.html")


@ app.route("/helper-register", methods=["GET", "POST"])
def helper_register():
    """Register helper"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure first name was submitted
        if not request.form.get("firstname"):
            return template("helper-register.html", "Insert First Name!", 400)

        # Ensure last name was submitted
        if not request.form.get("lastname"):
            return template("helper-register.html", "Insert last Name!", 400)

        # Ensure email was submitted
        if not request.form.get("email"):
            return template("helper-register.html", "Insert Email!", 400)

        # Query database for email
        db.execute("SELECT * FROM helper WHERE email = ?",
                   (request.form.get("email"),))
        rows = db.fetchall()

        # Ensure new email doesn't exist
        if len(rows) != 0:
            return template("helper-register.html", "Email already in use!", 400)

        # Ensure email was submitted
        if not request.form.get("email"):
            return template("helper-register.html", "Insert Email!", 400)

        # Query database for email
        db.execute("SELECT * FROM helper WHERE email = ?",
                   (request.form.get("email"),))
        specialty = db.fetchall()

        # Inserts new user to the database
        db.execute("INSERT INTO helpers(first_name, last_name, email, contact, specialty_id) VALUES(?, ?)", (request.form.get(
            "firstname"), request.form.get("lastname"), request.form.get("email"), request.form.get("contact"), ))

        # Redirect user to home page
        flash("You're registred!")
        return redirect("/login")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        db.execute("SELECT name FROM specialtys")
        specialtys = db.fetchall()
        return render_template("helper-register.html", specialtys=specialtys)


@ app.route("/user-register", methods=["GET", "POST"])
def user_register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure Username was submitted
        if not request.form.get("username"):
            return template("user-register.html", "Insert Username!", 400)

        db.execute("SELECT * FROM user WHERE username = ?",
                   (request.form.get("username"),))
        rows = db.fetchall()

        # Ensure new user doesn't exist
        if len(rows) != 0:
            return template("user-register.html", "Username already in use!", 400)

        # Ensure email was submitted
        if not request.form.get("email"):
            return template("user-register.html", "Insert Email!", 400)

        # Query database for email
        db.execute("SELECT * FROM user WHERE email = ?",
                   (request.form.get("email"),))
        rows = db.fetchall()

        # Ensure new user doesn't exist
        if len(rows) != 0:
            return template("user-register.html", "Email already in use!", 400)

        # Ensure password was submitted
        if not request.form.get("password"):
            return template("user-register.html", "Insert Password", 400)

        # Ensure confirmation equals password
        if request.form.get("password") != request.form.get("confirmation"):
            return template("user-register.html", "Passwords do not match!", 400)

        # Inserts new user to the database
        db.execute("INSERT INTO users(username, hash) VALUES(?, ?)", request.form.get("username"), generate_password_hash(
            request.form.get("password")))

        # Redirect user to home page
        flash("You're registred!")
        return redirect("/login")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("user-register.html")


@ app.route("/login", methods=["GET", "POST"])
def login():
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return template("login.html", "Must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return template("login.html", "Must provide password", 400)

        # Query database for email
        rows = db.execute("SELECT * FROM users WHERE username = ?",
                          request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return template("/login", "Invalid username and/or password", 400)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/homepage")

    else:
        return render_template("login.html")


@ app.route("/homepage", methods=["GET", "POST"])
# @login_required
def homepage():
    if request.method == "POST":
        # Ensure note is valid
        if not request.form.get("note"):
            return template("homepage.html", "Write a valid note!", 400)
        db.execute("SELECT * FROM user WHERE email = ?",
                   (request.form.get("email"),))
        return redirect("/homepage")
    else:
        db.execute("SELECT * FROM notes username = ?",
                   (request.form.get("email"),))
        notes = db.fetchall()
        return render_template("homepage.html", notes=notes)


@ app.route("/specialists", methods=["GET", "POST"])
# @login_required
def specialists():
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        return
    else:
        return render_template("specialists.html")


# Handle error
def errorhandler(e):
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return template("homepage.html", "Something Went Wrong", e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
