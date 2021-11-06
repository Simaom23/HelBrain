from flask import redirect, render_template, request, session, flash
from functools import wraps


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def template(template="login.html", message="Something Went Wrong", code=400):
    flash(message, code)
    return render_template(template)
