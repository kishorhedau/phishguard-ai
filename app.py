"""
PhishGuard AI – Flask Backend
Analyzes URLs for phishing risk and returns a JSON response.
"""

from flask import Flask, request, jsonify, render_template
import re

app = Flask(__name__)

# ─── Suspicious keywords that raise phishing risk ───────────────────────────
SUSPICIOUS_KEYWORDS = ["login", "verify", "bank", "secure", "account",
                       "update", "confirm", "password", "signin", "paypal",
                       "ebay", "amazon", "apple", "microsoft", "support",
                       "wallet", "urgent", "suspended", "free", "prize",
                       "crypto", "airdrop", "claim", "reset", "otp"]


def analyze_url(url: str) -> dict:
    """
    Analyze a URL for phishing indicators.
    Returns a dict with score, classification, and list of reasons.
    """
    score = 0
    reasons = []

    # ── 1. Check for HTTPS ──────────────────────────────────────────────────
    if not url.startswith("https://"):
        score += 30
        reasons.append({
            "icon": "🔓",
            "text": "No HTTPS – connection is not encrypted",
            "severity": "high"
        })

    # ── 2. Check for suspicious keywords ────────────────────────────────────
    url_lower = url.lower()
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if found_keywords:
        score += 20
        reasons.append({
            "icon": "⚠️",
            "text": f"Suspicious keywords detected: {', '.join(found_keywords)}",
            "severity": "medium"
        })

    # ── 3. Check URL length ──────────────────────────────────────────────────
    if len(url) > 50:
        score += 10
        reasons.append({
            "icon": "📏",
            "text": f"Unusually long URL ({len(url)} characters)",
            "severity": "low"
        })

    # ── 4. Check if URL uses an IP address instead of a domain ──────────────
    # Strip the scheme first, then check for IP pattern
    stripped = re.sub(r'^https?://', '', url)
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}'
    if re.match(ip_pattern, stripped):
        score += 25
        reasons.append({
            "icon": "🌐",
            "text": "IP address used instead of a domain name",
            "severity": "high"
        })

    # ── 5. Check for excessive subdomains (bonus heuristic) ─────────────────
    try:
        host = stripped.split('/')[0].split(':')[0]
        parts = host.split('.')
        if len(parts) > 4:
            score += 10
            reasons.append({
                "icon": "🔗",
                "text": f"Excessive subdomains detected ({len(parts)-2} levels deep)",
                "severity": "medium"
            })
    except Exception:
        pass

    # ── 6. Check for @ symbol in URL (common trick) ──────────────────────────
    if '@' in url:
        score += 15
        reasons.append({
            "icon": "🎭",
            "text": "@ symbol found – URL may be masking true destination",
            "severity": "high"
        })

    # ── Cap score at 100 ────────────────────────────────────────────────────
    score = min(score, 100)

    # ── Classify ─────────────────────────────────────────────────────────────
    if score < 30:
        classification = "Safe"
    elif score < 60:
        classification = "Suspicious"
    else:
        classification = "Dangerous"

    # If no issues were found, add a positive note
    if not reasons:
        reasons.append({
            "icon": "✅",
            "text": "No obvious phishing indicators detected",
            "severity": "none"
        })

    return {
        "score": score,
        "classification": classification,
        "reasons": reasons,
        "url": url
    }


# ─── Routes ─────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    """Serve the main HTML page."""
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    """
    POST /analyze
    Body: { "url": "https://example.com" }
    Returns: JSON with score, classification, and reasons
    """
    data = request.get_json()

    # Validate input
    if not data or 'url' not in data:
        return jsonify({"error": "Missing 'url' field in request body"}), 400

    url = data['url'].strip()

    if not url:
        return jsonify({"error": "URL cannot be empty"}), 400

    # Basic format check – must start with http:// or https://
    if not re.match(r'^https?://', url):
        return jsonify({"error": "URL must start with http:// or https://"}), 400

    # Run analysis
    result = analyze_url(url)
    return jsonify(result)


# ─── Entry Point ─────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("🛡️  PhishGuard AI server starting on http://127.0.0.1:5000")
    app.run(debug=True)
