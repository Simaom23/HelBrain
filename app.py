import sqlite3

from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import login_required, template, clean_data, check_password, clean_specialtys

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


@app.route("/", methods=["GET"])
def index():
    return redirect("/homepage")


@app.route("/register", methods=["GET", "POST"])
def register():
    return render_template("register.html")


@app.route("/helper-register", methods=["GET", "POST"])
def helper_register():
    """Register helper"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure specialty was submitted
        if not request.form.get("specialty"):
            return template("/helper-register", "Insert specialty!", 400)

        # Ensure first name was submitted
        if not request.form.get("name"):
            return template("/helper-register", "Insert your name!", 400)

        # Ensure email was submitted
        if not request.form.get("email"):
            return template("/helper-register", "Insert email!", 400)

        # Query database for email
        db.execute("SELECT * FROM helpers WHERE UPPER(email) = ?",
                   (request.form.get("email").upper(),))
        rows = db.fetchall()

        # Check if contact was submitted
        if not request.form.get("contact"):
            contact = None
        else:
            contact = request.form.get("contact")

        # Ensure new email doesn't exist
        if len(rows) != 0:
            return template("/helper-register", "Email already in use!", 400)

        # Query database for specialty id
        db.execute("SELECT id FROM specialtys WHERE name = ?",
                   (request.form.get("specialty"),))
        data = db.fetchall()
        specialty_id = clean_specialtys(data)

        # Inserts new user to the database
        db.execute("INSERT INTO helpers(name, email, contact, specialty_id) VALUES(?, ?, ?, ?)", (request.form.get(
            "name"), request.form.get("email"), contact, specialty_id[0],))
        database.commit()

        # Redirect user to home page
        flash("You're registred!")
        return redirect("/login")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        db.execute("SELECT name FROM specialtys ORDER BY name")
        data = db.fetchall()
        specialtys = clean_specialtys(data)

        return render_template("helper-register.html", specialtys=specialtys)


@app.route("/user-register", methods=["GET", "POST"])
def user_register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure Username was submitted
        if not request.form.get("username"):
            return template("/user-register", "Insert Username!", 400)

        db.execute("SELECT * FROM users WHERE UPPER(username) = ?",
                   (request.form.get("username").upper(),))
        rows = db.fetchall()

        # Ensure new user doesn't exist
        if len(rows) != 0:
            return template("/user-register", "Username already in use!", 400)

        # Ensure email was submitted
        if not request.form.get("email"):
            return template("/user-register", "Insert email!", 400)

        # Query database for email
        db.execute("SELECT * FROM users WHERE UPPER(email) = ?",
                   (request.form.get("email").upper(),))
        rows = db.fetchall()

        # Ensure new user doesn't exist
        if len(rows) != 0:
            return template("/user-register", "Email already in use!", 400)

        # Ensure password was submitted
        if not request.form.get("password"):
            return template("/user-register", "Insert password", 400)

        # Check if password as the specifications necessary
        check = check_password(request.form.get("password"))
        if check != "True":
            return template("/user-register", check, 400)

        # Ensure confirmation equals password
        if request.form.get("password") != request.form.get("confirmation"):
            return template("/user-register", "Passwords do not match!", 400)

        # Inserts new user to the database
        db.execute("INSERT INTO users(username, email, hash) VALUES(?, ?, ?)", (request.form.get("username"), request.form.get("email"), generate_password_hash(
            request.form.get("password")),))
        database.commit()

        # Redirect user to home page
        flash("You're registred!")
        return redirect("/login")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("user-register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Login user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return template("/login", "Must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return template("/login", "Must provide password", 400)

        # Query database for username
        db.execute("SELECT * FROM users WHERE UPPER(username) = ?", (
                   request.form.get("username").upper(),))
        data = db.fetchall()
        user = clean_data(data)

        # Ensure username exists and password is correct
        if len(data) != 1 or not check_password_hash(user[0][3], request.form.get("password")):
            return template("/login", "Invalid username and/or password", 400)

        # Remember which user has logged in
        session["user_id"] = user[0][0]

        # Redirect user to homepage
        return redirect("/homepage")

    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    """Change password"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure current password was submitted
        if not request.form.get("current"):
            return template("/password", "Insert current password", 400)

        # Query database for username
        db.execute("SELECT * FROM users WHERE id = ?",
                   (session.get("user_id"),))
        data = db.fetchall()
        user = clean_data(data)

        # Ensure username exists and password is correct
        if len(user) != 1 or not check_password_hash(user[0][3], request.form.get("current")):
            return template("/password", "Invalid current password", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return template("/password", "Insert new password", 400)

        check = check_password(request.form.get("password"))
        if check != "True":
            return template("/password", "New password doesn't have the required specifications", 400)

        # Ensure confirmation equals password
        elif request.form.get("password") != request.form.get("confirmation"):
            return template("/password", "New password doesn't match", 400)

        # Inserts new password hash to the database
        db.execute("UPDATE users SET hash=? WHERE id=?", (generate_password_hash(
            request.form.get("password")), session.get("user_id"),))
        database.commit()

        # Redirect user to home page
        flash('Password Changed!')
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("password.html")


@app.route("/homepage", methods=["GET", "POST"])
@login_required
def homepage():

    if request.method == "POST":

        # Ensure note is valid
        if not request.form.get("note"):
            return template("/homepage", "Write a valid note!", 400)

        # Insert note into database
        db.execute("INSERT INTO notes(user_id, note) VALUES(?, ?)",
                   (session["user_id"], request.form.get("note"),))
        database.commit()

        return redirect("/homepage")

    else:
        # Get notes from database
        db.execute("SELECT * FROM notes WHERE user_id = ? ORDER BY timestamp DESC LIMIT 20", (
            session["user_id"],))
        data = db.fetchall()
        notes = clean_data(data)

        # Get username from database
        db.execute("SELECT username FROM users WHERE id = ?", (
            session["user_id"],))
        data = db.fetchall()
        username = clean_data(data)

        return render_template("homepage.html", username=username[0][0], notes=notes)


@app.route("/specialists", methods=["GET", "POST"])
@login_required
def specialists():
    """Search for specialists"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Check if specialty and helpers name were not submitted
        if not request.form.get("specialty") and not request.form.get("helpersname"):
            return template("/specialists", "Insert specialty or helpers name!", 400)
        else:
            # Search helpers name on database
            if not request.form.get("specialty"):
                db.execute("SELECT * FROM helpers JOIN specialtys ON specialtys.id = helpers.specialty_id WHERE helpers.name = ?",
                           (request.form.get("helpersname"),))

            # Search specialtys name on database
            elif not request.form.get("helpersname"):
                db.execute("SELECT * FROM helpers JOIN specialtys ON specialtys.id = helpers.specialty_id WHERE specialtys.name = ?",
                           (request.form.get("specialty"),))

            else:
                db.execute("SELECT * FROM helpers JOIN specialtys ON specialtys.id = helpers.specialty_id WHERE specialtys.name = ? AND helpers.name = ?",
                           (request.form.get("specialty"), request.form.get("helpersname"),))
            data = db.fetchall()
            helpers = clean_data(data)

            # Get specialtys from databse
            db.execute("SELECT name FROM specialtys ORDER BY name")
            data = db.fetchall()
            specialtys = clean_specialtys(data)

            return render_template("specialists.html", specialtys=specialtys, helpers=helpers)
    else:
        # Get helpers from databse
        db.execute(
            "SELECT * FROM helpers JOIN specialtys ON specialtys.id = helpers.specialty_id ORDER BY helpers.name LIMIT 20")

        data = db.fetchall()
        helpers = clean_data(data)

        # Get specialtys from databse
        db.execute("SELECT name FROM specialtys ORDER BY name")
        data = db.fetchall()
        specialtys = clean_specialtys(data)

        return render_template("specialists.html", specialtys=specialtys, helpers=helpers)


# Handle error
def errorhandler(e):
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return template("/homepage", "Something Went Wrong", e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
