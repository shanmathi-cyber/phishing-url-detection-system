from flask import Flask, render_template, request
import tldextract

app = Flask(__name__)

def check_url(url):
    suspicious_keywords = [
        "login", "verify", "update", "secure",
        "bank", "account", "free", "reward"
    ]
    score = 0

    # Rule 1: Long URL
    if len(url) > 75:
        score += 1

    # Rule 2: Special characters
    if "@" in url or "-" in url:
        score += 1

    # Rule 3: Suspicious keywords
    for word in suspicious_keywords:
        if word in url.lower():
            score += 1

    # Rule 4: HTTPS check
    if not url.startswith("https://"):
        score += 1

    # Final result
    if score >= 3:
        return "🚨 Phishing Website Detected"
    elif score == 2:
        return "⚠️ Suspicious Website"
    else:
        return "✅ Safe Website"

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        url = request.form.get("url")
        result = check_url(url)
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)

