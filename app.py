from flask import Flask, render_template, request
from urllib.parse import urlparse
import ipaddress
import re

app = Flask(__name__)

def analyze_url(url):
    score = 0
    warnings = []
    url = url.strip()

    test_url = url if re.match(r"^https?://", url, re.I) else "http://" + url

    try:
        parsed = urlparse(test_url)
        hostname = parsed.hostname

        if not hostname:
            return 10, "Invalid URL", ["Please enter a valid URL."]

        if parsed.scheme.lower() != "https":
            score += 2
            warnings.append("URL does not use HTTPS.")

        try:
            ipaddress.ip_address(hostname)
            score += 3
            warnings.append("URL uses an IP address instead of a domain.")
        except ValueError:
            pass

        suspicious_words = ["login", "verify", "password", "account", "update", "secure", "bank"]
        found = [w for w in suspicious_words if w in url.lower()]
        if found:
            score += min(len(found), 3)
            warnings.append("Suspicious keyword(s): " + ", ".join(found))

        if len(url) > 100:
            score += 1
            warnings.append("URL is unusually long.")

        if "@" in url:
            score += 2
            warnings.append("URL contains @ symbol.")

        if len(hostname.split(".")) >= 4:
            score += 1
            warnings.append("Domain contains many subdomains.")

        score = min(score, 10)

        if score <= 2:
            status = "Low Risk"
        elif score <= 5:
            status = "Medium Risk"
        else:
            status = "High Risk"

        if not warnings:
            warnings.append("No obvious warning signs detected.")

        return score, status, warnings

    except Exception:
        return 10, "Invalid URL", ["Unable to analyze this URL."]

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/checker", methods=["GET", "POST"])
def checker():
    result = None
    url = ""
    if request.method == "POST":
        url = request.form.get("url", "")
        if url.strip():
            score, status, warnings = analyze_url(url)
            result = {"score": score, "status": status, "warnings": warnings}
    return render_template("checker.html", result=result, url=url)

@app.route("/awareness")
def awareness():
    return render_template("awareness.html")

questions = [
    ("What is phishing?", ["A cyberattack that tricks users", "A programming language", "A database", "A hardware device"], 0),
    ("Which protocol normally provides encrypted web communication?", ["HTTP", "FTP", "HTTPS", "SMTP"], 2),
    ("What should you do with an unexpected suspicious link?", ["Click it", "Verify it independently", "Share it", "Enter your password"], 1),
    ("What makes a password stronger?", ["123456", "Your birthday", "A long unique password", "Your name"], 2),
    ("What does 2FA mean?", ["Two-Factor Authentication", "Two File Access", "Two Fast Apps", "Two Firewall Actions"], 0),
]

@app.route("/quiz", methods=["GET", "POST"])
def quiz():
    score = None
    if request.method == "POST":
        score = sum(
            1 for i, q in enumerate(questions)
            if request.form.get(f"q{i}") == str(q[2])
        )
    return render_template("quiz.html", questions=questions, score=score)

if __name__ == "__main__":
    app.run(debug=True)
