import struct
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
from dh import create_dh_key, calculate_dh_secret
from lib.helpers import appendSalt,appendMac,macCheck

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=True):
        self.conn = conn
        self.client = client
        self.server = server
        self.verbose = verbose
        self.shared_secret = None
        self.iv = None
        self.sequence_number = 1
        self.initiate_session()

    def initiate_session(self):
        # Initiation remains unchanged.
        # Assume the existence of dh.create_dh_key() and dh.calculate_dh_secret()
        # Those functions are placeholders for the actual Diffie-Hellman key exchange implementation
        my_public_key, my_private_key = create_dh_key()
        self.send(bytes(str(my_public_key), 'utf-8'), is_iv=True)  # Send my public key
        their_public_key = int(self.recv(is_iv=True))  # Receive their public key
        self.shared_secret = calculate_dh_secret(their_public_key, my_private_key)  # Calculate shared secret
        print("Shared hash: {}".format(self.shared_secret.hex()))

        if self.client:
            self.iv = get_random_bytes(AES.block_size)  # Client generates IV
            self.send(self.iv, is_iv=True)  # Send IV
        elif self.server:
            self.iv = self.recv(is_iv=True)  # Server receives IV

    def send(self, data, is_iv=False):
        if self.shared_secret and not is_iv:
            # Prepare data with timestamp and sequence number
            timestamp = int(time.time())
            header = struct.pack("I", timestamp) + struct.pack("I", self.sequence_number)
            self.sequence_number += 1  # Increment sequence number for next message

            # Encrypt the data
            cipher = AES.new(self.shared_secret, AES.MODE_CBC, self.iv)
            encrypted_data = cipher.encrypt(pad(header + data, AES.block_size))

            # Generate HMAC and salt
            data_to_send = appendSalt(appendMac(encrypted_data, self.shared_secret))
        else:
            data_to_send = data

        # Send data
        self.conn.sendall(struct.pack("H", len(data_to_send)) + data_to_send)

        if self.verbose:
            print()
            print("Sending: {}".format(data))
            print("Encrypted data: {}".format(repr(data_to_send)))
            print("Sending packet of length: {}".format(len(data_to_send)))
            print()

    def recv(self, is_iv=False):
        # Receive packet length
        pkt_len_packed = self.conn.recv(struct.calcsize("H"))
        pkt_len = struct.unpack("H", pkt_len_packed)[0]

        # Receive the actual data
        data = self.conn.recv(pkt_len)

        if self.shared_secret and not is_iv:
            # Extract encrypted data, HMAC, and salt
            encrypted_data = data[:-40]  # Exclude HMAC (32 bytes) and salt (8 bytes)
            received_hmac = data[-40:-8]
            salt = data[-8:]

            # Verify HMAC
            if not macCheck(encrypted_data, received_hmac, self.shared_secret):
                raise ValueError("MAC verification failed.")

            # Decrypt the data
            cipher = AES.new(self.shared_secret, AES.MODE_CBC, self.iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

            # Extract timestamp and sequence number
            timestamp, sequence_number = struct.unpack("II", decrypted_data[:8])
            message = decrypted_data[8:]

            # Check timestamp
            current_time = int(time.time())
            if abs(current_time - timestamp) > 30:  # Allow a maximum drift of 30 seconds
                raise ValueError("Message timestamp is too old or too new.")

            # Check sequence number
            if sequence_number != self.sequence_number:
                raise ValueError("Unexpected sequence number.")
            self.sequence_number += 1  # Increment sequence number for the next expected message

            if self.verbose:
                print()
                print("Receiving message of length: {}".format(len(encrypted_data)))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original message: {}".format(message))
                print()

        else:
            message = data

        return message


    def close(self):
        self.conn.close()

