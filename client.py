from ftplib import FTP
import os, sys, random, struct, hashlib, hmac
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad

def hashf(fname,key):
    hash_sha1 = hmac.new(key, str.encode(''), hashlib.sha1)
    with open(fname, 'rb') as file:
        while True:
            chunk = file.read(64*1024)
            if len(chunk) == 0:
                break
            hash_sha1.update(chunk)
    return hash_sha1.hexdigest()

def encrypt_file(key, hkey, in_filename,chunksize=64*1024, out_filename=None):
    print("Encrypting File....")
    if not out_filename:
        out_filename = in_filename + '.enc'
    hash = hashf(in_filename, hkey)
    pub_key = open("public.pem", "rb").read()
    rsa_key = RSA.importKey(pub_key)
    rsa_key = PKCS1_OAEP.new(rsa_key)
    final_key = rsa_key.encrypt(key)
    hkey = rsa_key.encrypt(hkey)
    iv = Random.get_random_bytes(16)
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)
	
    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(str.encode(hash))
            outfile.write(hkey)
            outfile.write(final_key)
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk)%16 == 0:
                    outfile.write(encryptor.encrypt(chunk))
                else:
                    outfile.write(encryptor.encrypt(pad(chunk,16)))
    print("Encryption Completed")
    return out_filename	

ftp = FTP('')
ftp.connect('localhost',1026)
ftp.login()
filepath = sys.argv[1]

print("[!] Getting public key...")
localfile = open('public.pem', 'wb')
ftp.retrbinary('RETR ' + 'public.pem', localfile.write, 1024)
localfile.close()

aes_key = os.urandom(32)
hkey = os.urandom(16)
filename = encrypt_file(aes_key, hkey, filepath)

print("Transfering File...")
ftp.storbinary('STOR '+filename, open(filename, 'rb'))
print("Transfer Completed")
os.system("rm "+filename)
ftp.quit()
