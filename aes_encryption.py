# ----------------------------------------------------------------------
# Author: yjj
# Purpose:
#     AES (CBC mode) encryption and decryption using custom key and iv
# Modified from:
#     https://blog.csdn.net/wang_hugh/article/details/83994750
# To test:
#     https://www.devglan.com/online-tools/aes-encryption-decryption
# ----------------------------------------------------------------------
import re
import base64
import binascii
from Crypto.Cipher import AES


class MyAESEncryption:

    def __init__(self, key, iv, output_format="base64"):

        if output_format!="base64" and output_format!="hex":
            raise Exception("output_format must be base64 or hex")

        self.key = key
        self.iv = iv
        self.mode = AES.MODE_CBC
        self.bs = 16  # block size
        self.output_format = output_format  # base64 or hex
        self.PADDING = lambda s: s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    def encrypt(self, text):
        generator = AES.new(self.key, self.mode, self.iv)
        crypt = generator.encrypt(self.PADDING(text))
        crypted_str = binascii.b2a_hex(crypt) if self.output_format=="hex" else base64.b64encode(crypt)
        result = crypted_str.decode()
        return result


    def decrypt(self, text):
        generator = AES.new(self.key, self.mode, self.iv)
        text += (len(text) % 4) * '='
        decrypt_bytes = binascii.a2b_hex(text) if self.output_format=="hex" else base64.b64decode(text)
        meg = generator.decrypt(decrypt_bytes)

        # remove illegal characters after decoding
        try:
            result = re.compile('[\\x00-\\x08\\x0b-\\x0c\\x0e-\\x1f\n\r\t]').sub('', meg.decode())
        except Exception:
            result = 'Decoding Error!!!'
        return result


if __name__ == '__main__':

    # change accordingly
    encrypt_key = 'aesEncryptionKey'   # AES key must be either 16, 24, or 32 bytes long
    encrypt_iv = 'encryptionIntVec'    # IV must be 16 bytes long
    to_encrypt = 'Hello World'

    aes_encyption = MyAESEncryption(encrypt_key, encrypt_iv, "base64")
    encrypted = aes_encyption.encrypt(to_encrypt)
    print("\n\tencryption: {0} ---> {1}".format(to_encrypt, encrypted))

    decrypted = aes_encyption.decrypt(encrypted)
    print("\tdecryption: {0} ---> {1}".format(encrypted, decrypted))