import hashlib
from base64 import b64decode, b64encode
from typing import Union

from Crypto import Random
from Crypto.Cipher import AES


class Encoder(object):

    def __init__(self):
        self.block_size = AES.block_size  # AES algo

    def __pad(self, plain_text: str) -> str:
        number_of_bytes_to_pad = self.block_size - \
            len(plain_text) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plain_text = plain_text + padding_str
        return padded_plain_text

    def __unpad(self, plain_text: str) -> str:
        last_character = plain_text[len(plain_text) - 1:]
        return plain_text[:-ord(last_character)]

    def aes_encrypt(self, plain_text: str, key: str) -> str:
        """
        Algorithm - AES
        One of the best ways to encrypt data, 
        in this case using 256 bit form

        Args:
            plain_text (str): source text to encrypt
            key (str): the key with which the message will be decrypted

        Returns:
            str: encrypted text
        """
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(hashlib.sha256(
            key.encode()).digest(), AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return b64encode(iv + encrypted_text).decode("utf-8")

    def aes_decrypt(self, encrypted_text: str, key: str) -> str:
        """

        Args:
            encrypted_text (str): encrypted text
            key (str): key used for encryption

        Returns:
            str: source text
        """
        encrypted_text = b64decode(encrypted_text)
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(hashlib.sha256(
            key.encode()).digest(), AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(
            encrypted_text[self.block_size:]).decode("utf-8")
        return self.__unpad(plain_text)

    # encoder = Encoder()
    # message = "test"
    # key = "12345"
    # en = encoder.aes_encrypt(message, key)
    # print(en)
    # print(encoder.aes_decrypt(en, key))
