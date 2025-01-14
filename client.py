import socket
import pickle
import os
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

HOST = '127.0.0.1'
PORT = 8080
KEY_FILE = "client_private.pem"
PUB_KEY_FILE = "client_public.pem"

# Генерация или загрузка ключей
if not os.path.exists(KEY_FILE):
    key = RSA.generate(2048)
    with open(KEY_FILE, 'wb') as f:
        f.write(key.export_key())
    with open(PUB_KEY_FILE, 'wb') as f:
        f.write(key.publickey().export_key())
else:
    with open(KEY_FILE, 'rb') as f:
        key = RSA.import_key(f.read())
    with open(PUB_KEY_FILE, 'rb') as f:
        public_key = RSA.import_key(f.read())

private_key = key
public_key = key.publickey()

# Клиентский сокет
sock = socket.socket()
sock.connect((HOST, PORT))
print(f"Подключено к серверу {HOST}:{PORT}")

# Отправка своего открытого ключа серверу
sock.send(public_key.export_key())

# Прием открытого ключа сервера
server_public_key_data = sock.recv(4096)
server_public_key = RSA.import_key(server_public_key_data)

# Отправка зашифрованного сообщения серверу
message = "Привет от клиента!"
cipher_rsa = PKCS1_OAEP.new(server_public_key)
encrypted_msg = cipher_rsa.encrypt(message.encode())
sock.send(encrypted_msg)

# Прием зашифрованного ответа от сервера
encrypted_response = sock.recv(4096)
cipher_rsa = PKCS1_OAEP.new(private_key)
decrypted_response = cipher_rsa.decrypt(encrypted_response)
print(f"Ответ сервера: {decrypted_response.decode()}")

sock.close()
