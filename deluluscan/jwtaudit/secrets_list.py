"""Common/default HS256 signing secrets to try against a captured JWT — the ones
that show up in tutorials, boilerplates, and framework defaults. A hit means the
key is guessable and any token can be forged. Small, curated, offline."""

WEAK_SECRETS = [
    "secret", "secretkey", "secret_key", "your-256-bit-secret", "your_jwt_secret",
    "jwt_secret", "jwtsecret", "changeme", "change-me", "password", "passw0rd",
    "admin", "test", "key", "private", "s3cr3t", "supersecret", "super_secret",
    "mysecret", "mysecretkey", "topsecret", "default", "example", "demo",
    "0000000000000000", "1234567890", "qwerty", "letmein", "123456", "12345678",
    "token", "auth", "authsecret", "signingkey", "signing_key", "hmac", "sha256",
    "your-secret-key", "your_secret_key", "MyVerySecretKey", "keyboard cat",
    "iloveyou", "welcome", "root", "toor", "dev", "development", "prod", "production",
    "aaaaaaaaaaaaaaaa", "secret123", "P@ssw0rd", "jwtkey", "jsonwebtoken",
]
