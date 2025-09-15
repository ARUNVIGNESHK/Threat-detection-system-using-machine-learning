import os
import csv
from collections import Counter
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import pickle
import pandas as pd
from extract_features import extract_file_features
from pcap_rules import analyze_pcap_rules
from utils.password_utils import check_password_strength

# ---------------- Flask Setup ---------------- #
app = Flask(__name__)
app.secret_key = "supersecretkey"
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# CSV file to store users
USERS_CSV = "users.csv"
if not os.path.exists(USERS_CSV):
    with open(USERS_CSV, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["username", "password"])  

# ---------------- Utilities ---------------- #
def load_feature_list(path_base_without_ext):
    pkl_path = f"{path_base_without_ext}.pkl"
    txt_path = f"{path_base_without_ext}.txt"
    if os.path.exists(pkl_path):
        with open(pkl_path, "rb") as f:
            return list(pickle.load(f))
    if os.path.exists(txt_path):
        with open(txt_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    raise FileNotFoundError(f"Feature list not found: {path_base_without_ext}")

def compute_summary(predictions):
    return dict(Counter(predictions))

def align_features(df: pd.DataFrame, feature_list):
    df.columns = df.columns.astype(str).str.strip()
    missing = [c for c in feature_list if c not in df.columns]
    for c in missing:
        df[c] = 0
    df = df[feature_list]
    df = df.apply(pd.to_numeric, errors="coerce").fillna(0)
    return df

def predict_with_model(df, model, scaler, label_map=None, model_name="Label"):
    if df.empty or (df.sum(axis=1) == 0).all():
        return [f"⚠️ {model_name}"]

    df_scaled = scaler.transform(df.to_numpy())
    preds = model.predict(df_scaled)

    if label_map:
        preds = [label_map.get(p, p) for p in preds]

    results = []
    for p in preds:
        label = str(p).lower().strip()
        if label in ["benign", "clean", "normal", "0"]:
            results.append("✅ Clean")
        else:
            if model_name.lower() == "malware":
                results.append("⚠️ Malware")
            elif model_name.lower() == "trojan":
                results.append("⚠️ Trojan")
            elif model_name.lower() == "attack":
                results.append(f"⚠️ Attack: {p}")
            else:
                results.append(f"⚠️ {p}")
    return results

# ---------------- Load ML Models & Features ---------------- #
malware_model = pickle.load(open("models/malware_model.pkl", "rb"))
malware_scaler = pickle.load(open("models/malware_scaler.pkl", "rb"))
malware_features = load_feature_list("models/malware_features")
malware_label_map = {0: "Clean", 1: "Malware", "benign": "Clean", "malicious": "Malware"}

attack_model = pickle.load(open("models/attack_model.pkl", "rb"))
attack_scaler = pickle.load(open("models/attack_scaler.pkl", "rb"))
attack_label_map = pickle.load(open("models/attack_label_map.pkl", "rb"))
attack_features = load_feature_list("models/attack_features")

trojan_model = pickle.load(open("trojan_models/trojan_model.pkl", "rb"))
trojan_scaler = pickle.load(open("trojan_models/trojan_scaler.pkl", "rb"))
trojan_features = load_feature_list("trojan_models/trojan_features")
trojan_label_map = {0: "Clean", 1: "Trojan", "benign": "Clean", "malicious": "Trojan"}

# ---------------- User Management (CSV) ---------------- #
def get_all_users():
    users = {}
    with open(USERS_CSV, "r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            users[row["username"]] = row["password"]
    return users

def register_user(username, password):
    users = get_all_users()
    if username in users:
        return False, "⚠️ Username already exists!"
    hashed = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)
    with open(USERS_CSV, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([username, hashed])
    return True, "✅ Registration successful!"

def validate_login(username, password):
    users = get_all_users()
    if username in users and check_password_hash(users[username], password):
        return True
    return False

# ---------------- Routes ---------------- #
@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            flash("⚠️ Please enter both username and password.", "warning")
            return redirect(url_for("login"))
        if validate_login(username, password):
            session["username"] = username
            flash(f"✅ Welcome back, {username}!", "success")
            return redirect(url_for("dashboard"))
        flash("❌ Invalid username or password", "danger")
        return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("👋 You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if not username or not password:
            flash("⚠️ Username and password required.", "danger")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("⚠️ Passwords do not match.", "danger")
            return redirect(url_for("register"))

        strength = check_password_strength(password)
        if strength == "Weak":
            flash("⚠️ Password too weak. Use uppercase, lowercase, number, and special character.", "danger")
            return redirect(url_for("register"))

        success, msg = register_user(username, password)
        flash(msg, "success" if success else "danger")
        if success:
            return redirect(url_for("login"))
        else:
            return redirect(url_for("register"))

    return render_template("register.html")

# ---------------- Dashboard ---------------- #
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "username" not in session:
        flash("⚠️ Please login first.", "warning")
        return redirect(url_for("login"))


    results = {
        "Malware": {"preview": None, "preds": None, "summary": None},
        "Attack": {"preview": None, "preds": None, "summary": None, "rules": None},
        "Trojan": {"preview": None, "preds": None, "summary": None},
    }

    if request.method == "POST":
        # ---------- Malware ---------- #
        file = request.files.get("malware_file")
        if file and file.filename:
            path = os.path.join(app.config["UPLOAD_FOLDER"], secure_filename(file.filename))
            file.save(path)
            try:
                ext = os.path.splitext(file.filename)[1].lower().lstrip(".")
                df_raw = extract_file_features(path, model_type="malware", filetype=ext, feature_list=malware_features)
                df_aligned = align_features(df_raw, malware_features)
                results["Malware"]["preview"] = df_aligned.head().to_html(classes="table table-sm table-bordered table-hover", index=False)
                results["Malware"]["preds"] = predict_with_model(df_aligned, malware_model, malware_scaler, malware_label_map, "Malware")
                results["Malware"]["summary"] = compute_summary(results["Malware"]["preds"])
            except Exception as e:
                flash(f"❌ Error processing Malware file: {e}", "danger")

        # ---------- Attack ---------- #
        file = request.files.get("attack_file")
        if file and file.filename:
            path = os.path.join(app.config["UPLOAD_FOLDER"], secure_filename(file.filename))
            file.save(path)
            try:
                ext = os.path.splitext(file.filename)[1].lower().lstrip(".")
                if ext == "pcap":
                    df_rules, rule_summary = analyze_pcap_rules(path)
                    if df_rules is not None and not df_rules.empty:
                        results["Attack"]["preview"] = df_rules.head(20).to_html(classes="table table-sm table-bordered table-hover", index=False)
                        results["Attack"]["summary"] = dict(df_rules["attack_type"].value_counts())
                        results["Attack"]["rules"] = rule_summary
                    else:
                        results["Attack"]["preview"] = "<em>No valid packets found in PCAP.</em>"
                        results["Attack"]["summary"] = {}
                else:
                    df_raw = extract_file_features(path, model_type="attack", filetype=ext, feature_list=attack_features)
                    df_aligned = align_features(df_raw, attack_features)
                    results["Attack"]["preview"] = df_aligned.head().to_html(classes="table table-sm table-bordered table-hover", index=False)
                    results["Attack"]["preds"] = predict_with_model(df_aligned, attack_model, attack_scaler, attack_label_map, "Attack")
                    results["Attack"]["summary"] = compute_summary(results["Attack"]["preds"])
            except Exception as e:
                flash(f"❌ Error processing Attack file: {e}", "danger")

        # ---------- Trojan ---------- #
        file = request.files.get("trojan_file")
        if file and file.filename:
            path = os.path.join(app.config["UPLOAD_FOLDER"], secure_filename(file.filename))
            file.save(path)
            try:
                ext = os.path.splitext(file.filename)[1].lower().lstrip(".")
                df_raw = extract_file_features(path, model_type="trojan", filetype=ext, feature_list=trojan_features)
                df_aligned = align_features(df_raw, trojan_features)
                results["Trojan"]["preview"] = df_aligned.head().to_html(classes="table table-sm table-bordered table-hover", index=False)
                results["Trojan"]["preds"] = predict_with_model(df_aligned, trojan_model, trojan_scaler, trojan_label_map, "Trojan")
                results["Trojan"]["summary"] = compute_summary(results["Trojan"]["preds"])
            except Exception as e:
                flash(f"❌ Error processing Trojan file: {e}", "danger")

    return render_template("dashboard.html", username=session.get("username", "Guest"), results=results)

# ---------------- Main ---------------- #
if __name__ == "__main__":
    app.run(debug=True) 