import os
key = os.urandom(24)
key_hex = key.hex()
print(f"clé: {key_hex}") 