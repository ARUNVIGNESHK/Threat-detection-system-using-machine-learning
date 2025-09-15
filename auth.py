# auth.py
from flask import Blueprint, render_template, redirect, url_for, request, flash
from models import User
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required
from utils.password_utils import check_password_strength  # custom password checker

# Create Blueprint
auth = Blueprint("auth", __name__)

# -------------------
# LOGIN
# -------------------
@auth.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash(f"👋 Welcome back, {username}!", "success")
            return redirect(url_for("home"))
        else:
            flash("❌ Invalid username or password", "danger")

    return render_template("login.html")


# -------------------
# REGISTER
# -------------------
@auth.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        # Username check
        if User.query.filter_by(username=username).first():
            flash("⚠️ Username already exists. Choose another one.", "warning")
            return redirect(url_for("auth.register"))

        # Confirm password check
        if password != confirm_password:
            flash("⚠️ Passwords do not match.", "danger")
            return redirect(url_for("auth.register"))

        # Password strength check
        strength = check_password_strength(password)
        if strength == "Weak":
            flash("⚠️ Password too weak. Use uppercase, lowercase, numbers, and special characters.", "danger")
            return redirect(url_for("auth.register"))

    return render_template("register.html")


# -------------------
# LOGOUT
# -------------------
@auth.route("/logout")
@login_required
def logout():
    logout_user()
    flash("👋 You have been logged out.", "info")
    return redirect(url_for("auth.login"))