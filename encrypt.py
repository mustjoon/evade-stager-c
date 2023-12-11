from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
filename = './www/encrypted-payload'
inputfile = "./GIGANTIC_JUNKER.bin"
#sensitive_data = b"ALIENS DO EXIST!!!!"
sensitive_data = open(inputfile, "rb").read()
key = b"AAAAAAAAAAAAAAAA" #must be 16, 24 or 32 bytes long
iv = b"AAAAAAAAAAAAAAAA"
cipher = AES.new(key, AES.MODE_CBC, iv = iv)
ciphertext = cipher.encrypt(pad(sensitive_data, AES.block_size))




res = open(filename, "w")
res.write(b64encode(ciphertext).decode('utf-8'))

print("Payload saved to "+ filename)