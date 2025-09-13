import base64
import hashlib
import sys
from cryptography.fernet import Fernet

def generate_fernet_key(secret_key: str) -> bytes:
  digest = hashlib.sha256(secret_key.encode()).digest()

  return base64.urlsafe_b64encode(digest)

def encrypt_password(password: str, secret_key: str) -> str:
  fernet_key = generate_fernet_key(secret_key)
  fernet = Fernet(fernet_key)
  return fernet.encrypt(password.encode()).decode()

def main():
  if len(sys.argv) < 3:
    print("Usage: python script.py <JWT_SECRET_KEY> <password_or_token>")
    sys.exit(1)

  secret_key = sys.argv[1]
  value = sys.argv[2]

  encrypted = encrypt_password(value, secret_key)
  print(f"Encrypted password: {encrypted}")

if __name__ == "__main__":
  main()