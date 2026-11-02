"""Quick test suite - run:  python test_cybershield.py"""
from security_modules import analyze_password, analyze_url, encrypt_bytes, decrypt_bytes, file_hashes

print("=== MODULE 1: Password Analyzer ===")
for pw in ["password", "Qwerty@2024", "T7#kp!Lz9$wQ2&mV"]:
    r = analyze_password(pw)
    print(f"{pw:20} -> {r['strength']:12} entropy={r['entropy_bits']:6} crack={r['crack_time']}")
assert analyze_password("password")["score"] == 0
assert analyze_password("T7#kp!Lz9$wQ2&mV")["score"] >= 3

print("\n=== MODULE 2: Phishing URL Detector ===")
for u in ["https://www.google.com", "http://paypa1.com/login/verify-account",
          "http://192.168.10.5/sbi/kyc-update.php",
          "http://secure-login.amazon.account-verify.xyz/signin",
          "https://www.google.com@evil-site.tk/free-bonus"]:
    r = analyze_url(u)
    print(f"{r['risk_score']:3}/100  {r['verdict']:22} {u}")
assert analyze_url("https://www.google.com")["verdict"] == "LIKELY SAFE"
assert analyze_url("http://paypa1.com/login/verify-account")["risk_score"] >= 50

print("\n=== MODULE 3: AES-256-GCM Encryption ===")
data = b"Top secret exam paper"
enc = encrypt_bytes(data, "MyPass@123")
assert decrypt_bytes(enc, "MyPass@123") == data
print("Encrypt/decrypt round-trip: OK")
try:
    decrypt_bytes(enc, "wrong"); raise SystemExit("FAIL")
except ValueError as e:
    print("Wrong password detected:", e)
tampered = bytearray(enc); tampered[-1] ^= 1
try:
    decrypt_bytes(bytes(tampered), "MyPass@123"); raise SystemExit("FAIL")
except ValueError:
    print("Tampering (1 bit flipped) detected: OK")
print("SHA-256:", file_hashes(data)["sha256"])
print("\nALL TESTS PASSED ✅")
