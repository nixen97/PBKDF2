import pbkdf2
from base64 import b64decode

a = pbkdf2.PBKDF2("password", "salt", 15000)

print(b64decode(a.GetBytes()))
