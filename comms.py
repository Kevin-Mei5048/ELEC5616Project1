import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
from dh import create_dh_key, calculate_dh_secret
from lib.helpers import appendMac, macCheck, appendSalt

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=True):
        self.conn = conn
        self.client = client
        self.server = server
        self.verbose = verbose
        self.shared_secret = None 
        self.iv = None
        self.initiate_session()

    def initiate_session(self):
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            self.send(bytes(str(my_public_key), "ascii"), is_iv=True)  # send my public key
            their_public_key = int(self.recv(is_iv=True))  # receive their public key
            self.shared_secret = calculate_dh_secret(their_public_key, my_private_key)  # calculate shared secret
            print("Shared hash: {}".format(self.shared_secret.hex()))

            if self.client:
                self.iv = get_random_bytes(AES.block_size)  # client generates IV
                self.send(self.iv, is_iv=True)
            elif self.server:
                self.iv = self.recv(is_iv=True)  # server receives IV from client


    def send(self, data, is_iv=False):
        if self.shared_secret and not is_iv:
            cipher = AES.new(self.shared_secret, AES.MODE_CBC, self.iv)
            encrypted_data = cipher.encrypt(pad(data, AES.block_size))
            data_to_send = appendMac(encrypted_data, self.shared_secret)
        else:
            data_to_send = data

        self.conn.sendall(struct.pack("H", len(data_to_send)))
        self.conn.sendall(data_to_send)

        if self.verbose:
            print(f"Sending: {data}")
            print(f"Encrypted data: {repr(encrypted_data)}" if not is_iv else "Sending IV or public key.")
            print(f"Packet length: {len(data_to_send)}\n")

    def recv(self, is_iv=False):
        pkt_len_packed = self.conn.recv(struct.calcsize("H"))
        pkt_len = struct.unpack("H", pkt_len_packed)[0]
        data = self.conn.recv(pkt_len)

        if self.shared_secret and not is_iv:
            encrypted_data = data[:-32]  # SHA256=32byte
            received_mac = data[-32:]
            if macCheck(encrypted_data, received_mac, self.shared_secret):
                cipher = AES.new(self.shared_secret, AES.MODE_CBC, self.iv)
                original_msg = unpad(cipher.decrypt(encrypted_data), AES.block_size)
            else:
                raise ValueError("MAC verification failed.")
        else:
            original_msg = data

        if self.verbose:
            print(f"Receiving: {original_msg}")
            print(f"Encrypted data: {repr(data)}" if not is_iv else "Receiving IV or public key.")
            print("Original message confirmed.\n")

        return original_msg

    def close(self):
        self.conn.close()
