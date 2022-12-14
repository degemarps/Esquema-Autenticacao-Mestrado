# #!/usr/bin/env python3
#
# -*- coding: utf-8 -*-
import time
from socket import *
from random import randint
import ssl
import hashlib
import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64decode
from base64 import b64encode
import os

# Definição das variáveis
servidor = '192.168.30.2'
porta = 4000
preLogin = 'c1fa34b2'
prePass = '12ef567a'
preKey = '2b58934fa02f34f1'
key = 'ABC123ABC123ABC1'
Login = 'login'
Password = 'password'
ID = '37c04800123'
Ci = "ABC123ABC123"
Ri = "37c0480063021011988c0095"
Sid = "37c04800630"

initial_time = time.time()

cont = 0

while cont < 10000:
    # Cria o socket que será usado para a conexão SSL
    context = ssl.SSLContext()
    context.verify_mode = ssl.CERT_REQUIRED

    context.load_verify_locations("./mycert.pem")

    context.load_cert_chain(certfile="./mycert.pem", keyfile="./mycert.pem")

    clientSocket = socket()
    clientSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

    # Cria o socket seguro SSL
    secureClientSocket = context.wrap_socket(clientSocket)

    # Tenta se conectar com o servidor
    secureClientSocket.connect((servidor, porta))

    server_cert = secureClientSocket.getpeercert()

    secureClientSocket.send(('CONNECT' + ';' + str(Sid)).encode())

    # Fecha as conexões seguras
    secureClientSocket.close()
    clientSocket.close()

    # time.sleep(10)

    # Atibue uma nova porta para ser usada na próxima conexão
    novaPorta = 5000

    new_socket = socket()
    new_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

    # Tenta se conectar com o servidor
    connected = False
    while not connected:
        try:
            new_socket.connect((servidor, novaPorta))
            connected = True
        except Exception as e:
            pass

    Ci_enc = new_socket.recv(1024).decode()

    # Decripta a mensagem recebida
    decipher = AES.new(bytes(key, 'utf-8'), AES.MODE_ECB)
    Ci_enc = b64decode(Ci_enc[2:-1])
    Ci_dec = unpad(decipher.decrypt(Ci_enc), 16).decode()

    if str(Ci_dec) == str(Ci)[2:-1]:
        # print("Ci recebido")

        # Encripta a mensagem para enviar
        cipher = AES.new(bytes(key, 'utf-8'), AES.MODE_ECB)
        Ri_enc = cipher.encrypt(pad(bytes(str(Ri), 'utf-8'), 16))
        msg = b64encode(Ri_enc)

        new_socket.send(str(msg).encode())

        ok_rec = new_socket.recv(1024).decode()

        if str(ok_rec) == 'OK':
            # print('OK recebido')

            Hlogin_password_id = hashlib.sha1((str(ID) + str(Password) + str(Login)).encode()).hexdigest()

            # Encripta a mensagem para enviar
            cipher = AES.new(bytes(key, 'utf-8'), AES.MODE_ECB)
            Hlogin_pass_id_enc = cipher.encrypt(pad(bytes(str(Hlogin_password_id), 'utf-8'), 16))
            msg = b64encode(Hlogin_pass_id_enc)

            new_socket.send(str(msg).encode())

            auth_rec = new_socket.recv(1024).decode()

            if str(auth_rec) == 'Authorized':
                # print('Publicação Autorizada')

                client = mqtt.Client()
                client.connect("192.168.30.2", 1883, 60)
                client.publish("topic/test", "Hello world!")
                client.disconnect()

    new_socket.close()

    cont += 1

print("--- %.2f seconds ---" % (time.time() - initial_time))
