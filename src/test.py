import pbkdf2
from base64 import b64decode

a = pbkdf2.PBKDF2("password")

print(a.GetBytes())
print(a.GetB64())
print(a.GetHex())

print()
print(a.Hash())
