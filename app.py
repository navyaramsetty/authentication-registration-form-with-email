from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
import random, time
from flask import render_template

# ---------------- APP INIT ---------------- #
app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
mail = Mail(app)
jwt = JWTManager(app)

# ---------------- DATABASE MODEL ---------------- #
class User(db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20))
    address = db.Column(db.String(200))
    dob = db.Column(db.String(20))
    is_verified = db.Column(db.Boolean, default=False)

# ---------------- CREATE DB ---------------- #
with app.app_context():
    db.create_all()

# ---------------- OTP STORE ---------------- #
otp_store = {}

def generate_otp(email):
    otp = str(random.randint(100000, 999999))
    otp_store[email] = {
        "otp": otp,
        "time": time.time()
    }
    return otp

def verify_otp(email, otp):
    if email not in otp_store:
        return False

    data = otp_store[email]

    # Expire after 2 minutes
    if time.time() - data["time"] > 120:
        otp_store.pop(email, None)
        return False

    return data["otp"] == otp

# ---------------- EMAIL ---------------- #
def send_email(to, subject, body):
    try:
        msg = Message(subject, recipients=[to], sender=app.config["MAIL_USERNAME"])
        msg.html = body
        mail.send(msg)
    except Exception as e:
        print("Email Error:", e)

def send_otp_email(email, otp):
    body = f"""
    <h2>OTP Verification</h2>
    <h1 style="color:#4CAF50">{otp}</h1>
    <p>Valid for 2 minutes</p>
    """
    send_email(email, "OTP Verification", body)

def send_user_details_email(user):

    html = render_template(
        "email/user_card.html",
        name=user["name"],
        email=user["email"],
        phone=user["phone"],
        address=user["address"],
        dob=user["dob"]
    )

    send_email(user["email"], "🎉 Registration Successful", html)

# ---------------- HOME ---------------- #
@app.route("/")
def home():
    return redirect(url_for("register"))

# ---------------- REGISTER ---------------- #
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        email = request.form.get("email")

        # Duplicate Check
        if User.query.filter_by(email=email).first():
            flash("Email already registered")
            return redirect(url_for("register"))

        session["reg_data"] = {
            "name": request.form.get("name"),
            "email": email,
            "password": generate_password_hash(request.form.get("password")),
            "phone": request.form.get("phone"),
            "address": request.form.get("address"),
            "dob": request.form.get("dob")
        }

        otp = generate_otp(email)
        send_otp_email(email, otp)

        return redirect(url_for("verify"))

    return render_template("register.html")

# ---------------- VERIFY OTP ---------------- #
@app.route("/verify", methods=["GET", "POST"])
def verify():

    if "reg_data" not in session:
        return redirect(url_for("register"))

    if request.method == "POST":

        otp = request.form.get("otp")
        email = session["reg_data"]["email"]

        if verify_otp(email, otp):

            data = session["reg_data"]

            new_user = User(**data, is_verified=True)
            db.session.add(new_user)
            db.session.commit()

            send_user_details_email(data)

            session.pop("reg_data", None)

            flash("Registration successful. Please login.")
            return redirect(url_for("login"))

        else:
            flash("Invalid or expired OTP")

    return render_template("verify.html")

# ---------------- LOGIN ---------------- #
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):

            session["user"] = email
            session["jwt"] = create_access_token(identity=email)

            return redirect(url_for("dashboard"))

        flash("Invalid email or password")

    return render_template("login.html")

# ---------------- DASHBOARD ---------------- #
@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect(url_for("login"))

    user = User.query.filter_by(email=session["user"]).first()

    return render_template("dashboard.html", user=user)

# ---------------- ADMIN ---------------- #
@app.route("/admin")
def admin():

    users = User.query.all()
    return render_template("admin.html", users=users)

# ---------------- RESET PASSWORD ---------------- #
reset_tokens = {}

@app.route("/reset_request", methods=["GET", "POST"])
def reset_request():

    if request.method == "POST":

        email = request.form.get("email")

        if not User.query.filter_by(email=email).first():
            flash("Email not registered")
            return redirect(url_for("reset_request"))

        token = str(random.randint(100000, 999999))
        reset_tokens[email] = token

        link = url_for("reset_password", email=email, token=token, _external=True)

        send_email(email, "Reset Password", f"<a href='{link}'>Reset Password</a>")

        flash("Reset link sent to email")

    return render_template("reset_request.html")

@app.route("/reset_password/<email>/<token>", methods=["GET", "POST"])
def reset_password(email, token):

    if reset_tokens.get(email) != token:
        return "Invalid or expired token"

    if request.method == "POST":

        new_pass = request.form.get("password")

        user = User.query.filter_by(email=email).first()
        user.password = generate_password_hash(new_pass)

        db.session.commit()

        reset_tokens.pop(email, None)

        flash("Password reset successful")
        return redirect(url_for("login"))

    return render_template("reset_password.html")

# ---------------- LOGOUT ---------------- #
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------------- RUN ---------------- #
if __name__ == "__main__":
    app.run(debug=True)
