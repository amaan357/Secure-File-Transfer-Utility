from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
import os, struct, hashlib, hmac
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import unpad


def hashf(fname,key):											#function to calculate the HMAC of the given data
    hash_sha1 = hmac.new(key, str.encode(''), hashlib.sha1)
    with open(fname, 'rb') as file:
        while True:
            chunk = file.read(64*1024)
            if len(chunk) == 0:
                break
            hash_sha1.update(chunk)
    return hash_sha1.hexdigest()

def RSA_generate():														#function to generate the key pairs
    private_key = RSA.generate(1024)
    public_key = private_key.publickey()

    with open ("private.pem", "wb") as prv_file:
        prv_file.write(private_key.exportKey('PEM'))

    with open ("public.pem", "wb") as pub_file:
        pub_file.write(public_key.exportKey('PEM'))
	
def validateIntegrity(orighash, filepath, key):							#function to do the validation
    desthash = hashf(filepath, key)
    orighash = orighash.decode()
    if(orighash==desthash):
        return True 						
    else:
        os.system("rm " + filepath)
        return False	

def decrypt_file(in_filename, chunksize=64*1024, out_filename=None):	
    print("Decrypting File....")
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]

    with open(in_filename, 'rb') as infile:
        hash = infile.read(40)
        sec_key = infile.read(128)
        aes_key = infile.read(128)
        priv_key = open(anonymous + r"\private.pem", "rb").read()
        rsa_key = RSA.importKey(priv_key)
        rsa_key = PKCS1_OAEP.new(rsa_key)						
        hkey = rsa_key.decrypt(sec_key)
        aeskey = rsa_key.decrypt(aes_key)
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(aeskey, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                n = len(chunk)
                if n == 0:
                    break
                dec = decryptor.decrypt(chunk)
                if origsize > n:
                    outfile.write(dec)
                else:
                    outfile.write(unpad(dec,16))
                origsize -= n
        if(validateIntegrity(hash, out_filename, hkey)):	
            print("File decrypted and saved at " + out_filename)
        else:
            print("File was Corrupted and Hence Deleted")


class Custom_Handler(FTPHandler):									#overriding default FTP handler to trigger the decrypt functon on receiving file
	def on_file_received(self, filepath):	
		decrypt_file(filepath)					
		os.system("rm "+filepath)

		
anonymous = r"C:\Users\ADMIN\Desktop\Anonymous"

print("[!] Generating Key Pairs....")
RSA_generate()	
authorizer = DummyAuthorizer()
authorizer.add_anonymous(anonymous, perm="elradfmw")

handler = Custom_Handler
handler.authorizer = authorizer
handler.banner = "Ready to Receive File..."

server = FTPServer(("127.0.0.1", 1026), handler)
server.serve_forever()