import base64, hashlib, hmac, json

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def sign_jwt(payload, secret):
    hdr = b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64u(json.dumps(payload).encode())
    sig = b64u(hmac.new(secret.encode(), f"{hdr}.{body}".encode(), hashlib.sha256).digest())
    return f"{hdr}.{body}.{sig}"

def verify_jwt(tok, secret):
    hdr, body, sig = tok.split(".")
    exp = b64u(hmac.new(secret.encode(), f"{hdr}.{body}".encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(sig, exp): raise ValueError("Bad signature")
    pad = "=" * (-len(body) % 4)
    return json.loads(base64.urlsafe_b64decode(body + pad))

if __name__ == "__main__":
    t = sign_jwt({"sub": "itsmerbk"}, "supersecret")
    assert verify_jwt(t, "supersecret")["sub"] == "itsmerbk"
    print("[PASS] 072_jwt_hs256_signer")
