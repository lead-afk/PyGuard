import bcrypt
from pathlib import Path
Path('/etc/pyguard').mkdir(mode=0o700, exist_ok=True)
pw = input("Enter a strong password for the admin user: ")
h = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
Path('/etc/pyguard/admin.pass.hash').write_text(h)
import os
os.chmod('/etc/pyguard/admin.pass.hash', 0o600)
print('Wrote hash to /etc/pyguard')