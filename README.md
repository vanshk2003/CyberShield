# 🛡️ CyberShield – Mini Security Toolkit
**M.Tech Cybersecurity Mini Project (Group of 3)**

A web-based toolkit with three security modules:

| # | Module | Concepts covered | Presenter |
|---|--------|------------------|-----------|
| 1 | Password Strength Analyzer | Entropy, dictionary attacks, brute-force, hashing & salting, PBKDF2 | Member 1 |
| 2 | Phishing URL Detector | Social engineering, typosquatting, homograph attacks, heuristic detection | Member 2 |
| 3 | File Encryption & Integrity | AES-256-GCM, key derivation, CIA triad, SHA-256 hashing | Member 3 |

---

## ▶️ How to run

**Requirements:** Python 3.9 or newer.

```bash
# 1. Open a terminal inside the CyberShield folder
cd CyberShield

# 2. Install dependencies (one time)
pip install -r requirements.txt

# 3. (Optional) run the tests
python test_cybershield.py

# 4. Start the app
python app.py
```
Open **http://127.0.0.1:5000** in a browser. Stop with `Ctrl + C`.

**Windows tips:** if `python` isn't found, use `py app.py` and `py -m pip install -r requirements.txt`.
On Linux/Mac use `python3` / `pip3`.

### Project structure
```
CyberShield/
├── app.py                 # Flask web server + API routes
├── security_modules.py    # All the security logic (the important file)
├── templates/index.html   # Web UI
├── test_cybershield.py    # Automated tests
└── requirements.txt
```

---

## 🎯 Demo script (≈10 min)

**Intro (any member, 1 min):** "Most real attacks start with one of three things — a weak password, a phishing link, or unprotected data. CyberShield addresses all three, aligned with the CIA triad."

**Member 1 – Password Analyzer**
1. Type `password123` → Very Weak, cracked instantly (it's in a leaked-password list).
2. Type `Qwerty@2024` → looks complex but only Moderate, keyboard pattern detected.
3. Type `T7#kp!Lz9$wQ2&mV` → Very Strong, millions of centuries.
4. Scroll to the hash table; retype the same password → MD5/SHA-256 stay the same, PBKDF2 changes (random salt).

**Member 2 – Phishing Detector**
Click the sample buttons in order: `google.com` (safe) → `paypa1.com` (typosquatting) → `IP + KYC` → `amazon .xyz` → `@ trick`. Explain the table of indicators for each.

**Member 3 – Encryption & Integrity**
1. Encrypt any file (e.g. a .txt) with a password → downloads `file.txt.enc`. Open it in Notepad: unreadable.
2. Decrypt with the correct password → original file returns.
3. Decrypt with a wrong password → error shown (authentication fails).
4. Integrity: compute SHA-256 of a file, copy it, edit the file by one character, check again with the expected hash pasted → "HASH MISMATCH".

---

## 📘 Explanation of each module

### Module 1 – Password Strength Analyzer
- **Character pool (N):** lowercase 26 + uppercase 26 + digits 10 + symbols 32.
- **Entropy = L × log₂(N)** bits, where L is the length. Every extra bit doubles the attacker's work.
- **Penalties** because attackers don't brute-force blindly: common leaked password → entropy capped near 0; keyboard pattern (`qwerty`, `1234`) → ×0.6; repeated characters → ×0.8.
- **Crack time = 2^entropy ÷ 2 ÷ 10¹⁰** (average guesses at 10 billion/sec, a GPU rig on a fast hash).
- **Hashing demo:**
  - *MD5* – fast and broken; same password → same hash → rainbow tables work.
  - *SHA-256 unsalted* – secure algorithm, but still no salt → identical passwords share a hash.
  - *PBKDF2-SHA256 (200,000 iterations + 16-byte random salt)* – the salt defeats rainbow tables; the iterations make each guess 200,000× slower. This is how passwords should be stored (bcrypt/Argon2 are equivalents).

### Module 2 – Phishing URL Detector
A rule-based (heuristic) engine. Each rule adds points; total 0–100.
**≥50 Phishing · 25–49 Suspicious · <25 Likely Safe.**

| Rule | Why attackers do it | Points |
|---|---|---|
| Raw IP instead of domain | Avoids domain registration / reputation | 25 |
| No HTTPS | Cheap phishing pages often skip TLS | 10 |
| `@` in URL | Browser ignores text before `@` → `google.com@evil.tk` goes to evil.tk | 20 |
| URL > 75 chars | Hides the real domain off-screen | 10 |
| > 4 domain labels | `paypal.com.secure.evil.xyz` | 15 |
| Hyphen in domain | `paypal-secure.com` | 10 |
| Suspicious TLD (.xyz, .tk, .top…) | Free/cheap, heavily abused | 15 |
| URL shortener | Hides final destination | 15 |
| Keywords (login, verify, kyc…) | Urgency/credential lures | 5 each, max 20 |
| Brand name in non-brand domain | Impersonation | 25 |
| Typosquatting (Levenshtein ≤ 2) | `paypa1`, `gooogle` | 30 |
| Punycode `xn--` | Homograph: Cyrillic "а" looks like Latin "a" | 25 |
| Non-standard port / `//` in path | Hosting/redirect tricks | 10 |

**Levenshtein distance** = minimum single-character edits (insert/delete/replace) to turn one word into another; implemented with dynamic programming in `levenshtein()`.

**Limitation / future scope:** heuristics can have false positives; can be extended with ML (Random Forest on the PhishTank/UCI phishing datasets), WHOIS domain-age lookup, and Google Safe Browsing API.

### Module 3 – File Encryption & Integrity
**Encryption flow:**
```
password + random 16-byte salt ──PBKDF2-SHA256 (200k)──▶ 256-bit key
key + random 12-byte nonce + file ──AES-256-GCM──▶ ciphertext + 16-byte auth tag
Saved file = "CSHLD1" | salt | nonce | ciphertext+tag
```
- **AES-256** – symmetric block cipher, US government standard, 2²⁵⁶ keys.
- **GCM mode** – *authenticated encryption*: provides confidentiality **and** integrity. If the password is wrong or even one bit is altered, decryption fails (the tag doesn't match). This is why our tampering test passes.
- **Salt** – the same password gives a different key per file. **Nonce** – never reused, so the same file encrypts differently each time.
- **Integrity checker** – a hash is a one-way, fixed-length fingerprint; one changed byte → completely different hash (avalanche effect). Used to verify downloads, in malware signatures, and in digital forensics (chain of custody). MD5/SHA-1 are shown for comparison but are collision-broken; SHA-256 is the recommended one.

**CIA triad mapping:** Confidentiality → AES encryption · Integrity → GCM tag + SHA-256 · Authentication → strong passwords/PBKDF2.

---

## ❓ Likely viva questions

1. **Why not just use SHA-256 to store passwords?** It's too fast (billions/sec on GPUs) and unsalted hashes allow rainbow tables. Use a slow, salted KDF (PBKDF2/bcrypt/Argon2).
2. **Difference between encryption and hashing?** Encryption is reversible with a key; hashing is one-way.
3. **What is a salt vs a nonce?** Salt randomizes key/hash derivation; nonce ("number used once") randomizes each encryption. Both are public; neither is secret.
4. **Why GCM over CBC?** CBC gives only confidentiality and needs a separate MAC; GCM gives authenticated encryption in one step and avoids padding-oracle attacks.
5. **Symmetric vs asymmetric?** AES uses one shared key (fast, for data). RSA/ECC use public/private key pairs (for key exchange, signatures).
6. **Why is `Qwerty@2024` weak if it has all character types?** Attackers use dictionaries + rules (word + capital + symbol + year); entropy alone overestimates it.
7. **How would you reduce false positives in phishing detection?** Whitelist of top domains, domain age (WHOIS), ML model, reputation APIs.
8. **What is a homograph attack?** Using look-alike Unicode characters, e.g. `аpple.com` with a Cyrillic "а", encoded as punycode `xn--pple-43d.com`.

---

## Tech stack
Python 3 · Flask (web framework) · `cryptography` library (AES-GCM, PBKDF2) · `hashlib` · HTML/CSS/JavaScript
