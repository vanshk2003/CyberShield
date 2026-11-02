"""
CyberShield - Mini Security Toolkit (Flask web app)
Run:  python app.py   then open  http://127.0.0.1:5000
"""
import io
from flask import Flask, render_template, request, jsonify, send_file
from security_modules import (analyze_password, analyze_url, encrypt_bytes,
                              decrypt_bytes, file_hashes)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # 20 MB upload limit


@app.route("/")
def index():
    return render_template("index.html")


# ---------- Module 1 ----------
@app.post("/api/password")
def api_password():
    pw = (request.get_json() or {}).get("password", "")
    if not pw:
        return jsonify(error="Enter a password"), 400
    return jsonify(analyze_password(pw))


# ---------- Module 2 ----------
@app.post("/api/url")
def api_url():
    url = (request.get_json() or {}).get("url", "")
    if not url.strip():
        return jsonify(error="Enter a URL"), 400
    return jsonify(analyze_url(url))


# ---------- Module 3 ----------
@app.post("/api/encrypt")
def api_encrypt():
    f, pw = request.files.get("file"), request.form.get("password", "")
    if not f or not pw:
        return jsonify(error="File and password required"), 400
    out = encrypt_bytes(f.read(), pw)
    return send_file(io.BytesIO(out), as_attachment=True,
                     download_name=f.filename + ".enc")


@app.post("/api/decrypt")
def api_decrypt():
    f, pw = request.files.get("file"), request.form.get("password", "")
    if not f or not pw:
        return jsonify(error="File and password required"), 400
    try:
        out = decrypt_bytes(f.read(), pw)
    except ValueError as e:
        return jsonify(error=str(e)), 400
    name = f.filename[:-4] if f.filename.endswith(".enc") else "decrypted_" + f.filename
    return send_file(io.BytesIO(out), as_attachment=True, download_name=name)


@app.post("/api/hash")
def api_hash():
    f = request.files.get("file")
    if not f:
        return jsonify(error="File required"), 400
    return jsonify(file_hashes(f.read()))


if __name__ == "__main__":
    print("\n  CyberShield running ->  http://127.0.0.1:5000\n")
    app.run(debug=False, port=5000)
