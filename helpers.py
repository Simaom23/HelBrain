from flask import redirect, session, flash
from functools import wraps


# Login wrap
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


# Render error template
def template(template="/login", message="Something Went Wrong", code=400):
    flash(message)
    return redirect(template)


# Return clean data from Sqlite
def clean_data(data: list) -> list:
    clean_list = []
    for clean in data:
        clean_list.append(list(clean))
    return clean_list

# Return clean specialtys data from Sqlite


def clean_specialtys(data: list) -> list:
    clean_list = []
    for clean in data:
        clean_list.append(clean[0])
    return clean_list

# Checks for password


def check_password(password):
    """Checks if password is valid"""

    # String with special chars
    special_chars = "[@_!#$%^&*()<>?/|}{~:]"
    chars = 0
    numbers = 0
    special = 0

    # Checks if password is of at least size 10
    if len(password) < 10:
        return "Your password is too small"

    # Loops trough password
    for char in password:

        # Increments when char found
        if char.isalpha():
            chars += 1

        # Increments when number found
        elif char.isnumeric():
            numbers += 1

        # Increments when special character found
        elif char in special_chars:
            special += 1

        # Generates apology for invalid character
        else:
            return f"Invalid character ({char}) in password"

    # Generates apology for not enough characters
    if chars < 8:
        return "Password has to have at least 8 characters"

    # Generates apology for not enough numbers
    if numbers < 1:
        return "Password has to have at least 1 number"

    # Generates apology for not enough special characters
    if special < 1:
        return "Password has to have at least 1 special character"

    # Returns True for validated password
    return "True"
