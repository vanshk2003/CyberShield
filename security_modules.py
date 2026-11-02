"""
CyberShield - Core security logic
Module 1: Password Strength Analyzer & Secure Hashing
Module 2: Phishing URL Detector (heuristic / rule-based)
Module 3: File Encryption (AES-256-GCM) & Integrity Check (SHA-256)
"""
import hashlib
import ipaddress
import math
import os
import re
import string
from urllib.parse import urlparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# =====================================================================
# MODULE 1 : PASSWORD STRENGTH ANALYZER
# =====================================================================

# Small sample of the most common leaked passwords (RockYou-style list)
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "password1", "111111", "123123", "admin", "letmein",
    "welcome", "monkey", "dragon", "iloveyou", "sunshine", "princess",
    "football", "baseball", "master", "shadow", "superman", "qwerty123",
    "1q2w3e4r", "000000", "trustno1", "passw0rd", "india123", "admin123",
}
KEYBOARD_PATTERNS = ["qwerty", "asdf", "zxcv", "1234", "abcd", "qazwsx"]

GUESSES_PER_SECOND = 1e10  # offline attack with a modern GPU rig (fast hash)


def _human_time(seconds):
    if seconds < 1:
        return "instantly"
    units = [("centuries", 3153600000), ("years", 31536000), ("days", 86400),
             ("hours", 3600), ("minutes", 60), ("seconds", 1)]
    for name, size in units:
        if seconds >= size:
            value = seconds / size
            if name == "centuries" and value > 1e6:
                return "millions of centuries"
            return f"{value:,.0f} {name}"
    return "instantly"


def analyze_password(pw: str) -> dict:
    feedback = []
    pool = 0
    checks = {
        "length_8+": len(pw) >= 8,
        "length_12+": len(pw) >= 12,
        "lowercase": any(c.islower() for c in pw),
        "uppercase": any(c.isupper() for c in pw),
        "digits": any(c.isdigit() for c in pw),
        "symbols": any(c in string.punctuation for c in pw),
    }
    if checks["lowercase"]: pool += 26
    if checks["uppercase"]: pool += 26
    if checks["digits"]: pool += 10
    if checks["symbols"]: pool += len(string.punctuation)

    # Shannon-style brute-force entropy: L * log2(N)
    entropy = len(pw) * math.log2(pool) if pool else 0

    lower = pw.lower()
    is_common = lower in COMMON_PASSWORDS
    has_pattern = any(p in lower for p in KEYBOARD_PATTERNS)
    has_repeat = bool(re.search(r"(.)\1\1", pw))

    # Penalties model how real attackers use dictionaries & rules
    if is_common:
        entropy = min(entropy, 5)
        feedback.append("This is one of the most common leaked passwords!")
    if has_pattern:
        entropy *= 0.6
        feedback.append("Contains a keyboard/sequence pattern (qwerty, 1234...).")
    if has_repeat:
        entropy *= 0.8
        feedback.append("Avoid repeating the same character 3+ times.")
    if not checks["length_12+"]:
        feedback.append("Use at least 12 characters.")
    if not checks["uppercase"]: feedback.append("Add uppercase letters.")
    if not checks["digits"]: feedback.append("Add numbers.")
    if not checks["symbols"]: feedback.append("Add special symbols (!@#$...).")

    if entropy < 28: strength, score = "Very Weak", 0
    elif entropy < 36: strength, score = "Weak", 1
    elif entropy < 60: strength, score = "Moderate", 2
    elif entropy < 80: strength, score = "Strong", 3
    else: strength, score = "Very Strong", 4

    crack_seconds = (2 ** entropy) / 2 / GUESSES_PER_SECOND  # avg = half keyspace
    if not feedback:
        feedback.append("Great password! Store it in a password manager.")

    return {
        "length": len(pw),
        "charset_size": pool,
        "entropy_bits": round(entropy, 1),
        "strength": strength,
        "score": score,
        "crack_time": _human_time(crack_seconds),
        "is_common": is_common,
        "checks": checks,
        "feedback": feedback,
        "hashes": hash_demo(pw),
    }


def hash_demo(pw: str) -> dict:
    """Shows why plain hashes are bad and salted, slow KDFs are good."""
    salt = os.urandom(16)
    pbkdf2 = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000)
    return {
        "md5_insecure": hashlib.md5(pw.encode()).hexdigest(),
        "sha256_unsalted": hashlib.sha256(pw.encode()).hexdigest(),
        "pbkdf2_salt": salt.hex(),
        "pbkdf2_sha256_200k": pbkdf2.hex(),
    }


# =====================================================================
# MODULE 2 : PHISHING URL DETECTOR
# =====================================================================

TRUSTED_BRANDS = ["google", "facebook", "paypal", "amazon", "microsoft",
                  "apple", "netflix", "instagram", "sbi", "hdfcbank",
                  "icicibank", "paytm", "flipkart", "linkedin", "github"]
SUSPICIOUS_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "zip",
                   "click", "country", "work", "loan", "rest", "cam"}
SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
              "cutt.ly", "rb.gy"}
PHISH_KEYWORDS = ["login", "verify", "update", "secure", "account", "bank",
                  "confirm", "password", "signin", "wallet", "kyc", "reward",
                  "free", "bonus", "suspend", "unlock"]


def levenshtein(a: str, b: str) -> int:
    """Edit distance – used to detect typosquatting (paypa1 vs paypal)."""
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def analyze_url(url: str) -> dict:
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    findings = []  # (description, points)

    def flag(desc, pts):
        findings.append({"rule": desc, "points": pts})

    # 1. IP address instead of domain
    try:
        ipaddress.ip_address(host)
        flag("Uses a raw IP address instead of a domain name", 25)
    except ValueError:
        pass
    # 2. No HTTPS
    if parsed.scheme != "https":
        flag("Not using HTTPS (traffic is unencrypted)", 10)
    # 3. '@' symbol trick (browser ignores everything before @)
    if "@" in parsed.netloc or "@" in parsed.path:
        flag("Contains '@' – real destination may be hidden", 20)
    # 4. Long URL
    if len(url) > 75:
        flag(f"Very long URL ({len(url)} chars) – may hide the real domain", 10)
    # 5. Too many subdomains
    labels = host.split(".")
    if len(labels) > 4:
        flag(f"Too many subdomains ({len(labels) - 2})", 15)
    # 6. Hyphen in domain
    if "-" in host:
        flag("Hyphen in domain (e.g. paypal-secure.com)", 10)
    # 7. Suspicious TLD
    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        flag(f"Suspicious / cheap top-level domain '.{tld}'", 15)
    # 8. URL shortener
    if host in SHORTENERS:
        flag("URL shortener hides the final destination", 15)
    # 9. Phishing keywords
    kws = [k for k in PHISH_KEYWORDS if k in url.lower()]
    if kws:
        flag(f"Phishing keywords found: {', '.join(kws)}", min(5 * len(kws), 20))
    # 10. Brand impersonation & typosquatting
    registered = labels[-2] if len(labels) >= 2 else host
    for brand in TRUSTED_BRANDS:
        if brand in host and registered != brand:
            flag(f"Brand '{brand}' used in a domain it doesn't own", 25)
            break
        dist = levenshtein(registered, brand)
        if 0 < dist <= 2 and len(registered) >= 4:
            flag(f"Typosquatting: '{registered}' looks like '{brand}'", 30)
            break
    # 11. Punycode / homograph attack
    if "xn--" in host:
        flag("Punycode domain – possible homograph (look-alike letters) attack", 25)
    # 12. Non-standard port
    if parsed.port and parsed.port not in (80, 443):
        flag(f"Non-standard port :{parsed.port}", 10)
    # 13. Double slash redirect in path
    if "//" in parsed.path:
        flag("'//' in path – possible redirect trick", 10)

    score = min(sum(f["points"] for f in findings), 100)
    if score >= 50: verdict = "PHISHING / MALICIOUS"
    elif score >= 25: verdict = "SUSPICIOUS"
    else: verdict = "LIKELY SAFE"

    return {"url": url, "host": host, "risk_score": score,
            "verdict": verdict, "findings": findings}


# =====================================================================
# MODULE 3 : FILE ENCRYPTION (AES-256-GCM) & INTEGRITY (SHA-256)
# =====================================================================
MAGIC = b"CSHLD1"          # file header so we can recognise our files
SALT_LEN, NONCE_LEN = 16, 12
KDF_ITERATIONS = 200_000


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=KDF_ITERATIONS)
    return kdf.derive(password.encode())


def encrypt_bytes(data: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, data, MAGIC)  # header is authenticated
    # Layout: MAGIC | salt | nonce | ciphertext+16-byte GCM tag
    return MAGIC + salt + nonce + ciphertext


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    if not blob.startswith(MAGIC):
        raise ValueError("Not a CyberShield encrypted file.")
    off = len(MAGIC)
    salt = blob[off:off + SALT_LEN]
    nonce = blob[off + SALT_LEN:off + SALT_LEN + NONCE_LEN]
    ct = blob[off + SALT_LEN + NONCE_LEN:]
    key = _derive_key(password, salt)
    try:
        return AESGCM(key).decrypt(nonce, ct, MAGIC)
    except Exception:
        raise ValueError("Wrong password OR file has been tampered with!")


def file_hashes(data: bytes) -> dict:
    return {"md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "size_bytes": len(data)}
