import os
import sqlite3

from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from functools import wraps

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
# db = sqlite3.connect("sqlite:///app.db")


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


@app.route("/register", methods=["GET", "POST"])
def register():
    return render_template("register.html")


@app.route("/user-register", methods=["GET", "POST"])
def user_register():
    return render_template("user-register.html")


@app.route("/helper-register", methods=["GET", "POST"])
def helper_register():
    return render_template("helper-register.html")


@ app.route("/login", methods=["GET", "POST"])
def login():
    return render_template("login.html")


@ app.route("/helper-index")
def helper_index():
    return render_template("helper-index.html")


@ app.route("/user-index")
def user_index():
    return render_template("user-index.html")
