from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse
import ipaddress
from datetime import datetime


app = Flask(__name__)

app.config["SECRET_KEY"] = "phishguard-change-this-secret-key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///phishguard.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# -------------------------
# DATABASE MODELS
# -------------------------

class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(80),
        unique=True,
        nullable=False
    )

    password = db.Column(
        db.String(255),
        nullable=False
    )


class ScanHistory(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    url = db.Column(
        db.String(500),
        nullable=False
    )

    status = db.Column(
        db.String(30),
        nullable=False
    )

    score = db.Column(
        db.Integer,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


# -------------------------
# URL ANALYZER
# -------------------------

def analyze_url(url):

    score = 0
    reasons = []

    check_url = url if "://" in url else "http://" + url

    parsed = urlparse(check_url)

    hostname = parsed.hostname or ""


    # HTTPS

    if parsed.scheme != "https":

        score += 10

        reasons.append(
            "Connection is not using HTTPS"
        )


    # IP ADDRESS

    try:

        ipaddress.ip_address(hostname)

        score += 35

        reasons.append(
            "URL uses an IP address instead of a domain"
        )

    except ValueError:

        pass


    # @ SYMBOL

    if "@" in url:

        score += 25

        reasons.append(
            "URL contains an @ symbol"
        )


    # URL LENGTH

    if len(url) > 100:

        score += 15

        reasons.append(
            "URL is unusually long"
        )


    # SUBDOMAINS

    if hostname.count(".") >= 4:

        score += 20

        reasons.append(
            "Unusually high number of subdomains"
        )

    elif hostname.count(".") >= 3:

        score += 10

        reasons.append(
            "Multiple subdomains detected"
        )


    # KEYWORDS

    suspicious_words = [
        "login",
        "signin",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "bank",
        "password",
        "confirm",
        "wallet",
        "payment"
    ]

    for word in suspicious_words:

        if word in url.lower():

            score += 8

            reasons.append(
                f"Suspicious keyword detected: {word}"
            )


    # HYPHENS

    if hostname.count("-") >= 2:

        score += 15

        reasons.append(
            "Domain contains multiple hyphens"
        )


    # PORT

    try:

        if parsed.port is not None:

            if parsed.port not in [80, 443]:

                score += 15

                reasons.append(
                    f"Unusual network port: {parsed.port}"
                )

    except ValueError:

        score += 20

        reasons.append(
            "Invalid network port"
        )


    score = min(score, 100)


    if score < 30:

        status = "SAFE"

    elif score < 60:

        status = "SUSPICIOUS"

    else:

        status = "PHISHING"


    return {
        "status": status,
        "score": score,
        "reasons": reasons
    }


# -------------------------
# HOME
# -------------------------

@app.route("/")
def home():

    if "user_id" not in session:

        return redirect(url_for("login"))

    return render_template(
        "index.html",
        username=session.get("username")
    )


# -------------------------
# LOGIN
# -------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(
            username=username
        ).first()

        if user and check_password_hash(
            user.password,
            password
        ):

            session["user_id"] = user.id
            session["username"] = user.username

            return redirect(url_for("home"))

        return render_template(
            "login.html",
            error="Invalid username or password"
        )

    return render_template("login.html")


# -------------------------
# REGISTER
# -------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        existing = User.query.filter_by(
            username=username
        ).first()

        if existing:

            return render_template(
                "register.html",
                error="Username already exists"
            )

        hashed_password = generate_password_hash(
            password
        )

        user = User(
            username=username,
            password=hashed_password
        )

        db.session.add(user)

        db.session.commit()

        return redirect(url_for("login"))


    return render_template("register.html")


# -------------------------
# LOGOUT
# -------------------------

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# -------------------------
# SCAN
# -------------------------

@app.route("/scan", methods=["POST"])
def scan():

    if "user_id" not in session:

        return jsonify({
            "error": "Login required"
        }), 401


    data = request.get_json()

    url = data.get("url", "").strip()


    if not url:

        return jsonify({
            "status": "ERROR",
            "score": 0,
            "reasons": [
                "Please enter a URL"
            ]
        })


    result = analyze_url(url)


    # SAVE USER SCAN HISTORY

    history = ScanHistory(

        user_id=session["user_id"],

        url=url,

        status=result["status"],

        score=result["score"]

    )

    db.session.add(history)

    db.session.commit()


    return jsonify(result)


# -------------------------
# RECENT HISTORY
# -------------------------

@app.route("/history")
def history():

    if "user_id" not in session:

        return jsonify([])


    scans = ScanHistory.query.filter_by(

        user_id=session["user_id"]

    ).order_by(

        ScanHistory.created_at.desc()

    ).limit(10).all()


    return jsonify([

        {
            "url": scan.url,
            "status": scan.status,
            "score": scan.score,
            "time": scan.created_at.strftime(
                "%d %b %Y, %I:%M %p"
            )
        }

        for scan in scans

    ])


# -------------------------
# DATABASE
# -------------------------

with app.app_context():

    db.create_all()


# -------------------------
# RUN
# -------------------------

if __name__ == "__main__":

    app.run(debug=True)