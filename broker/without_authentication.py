# -*- coding: utf-8 -*-
import time
from socket import *
from random import randint
import ssl
import hashlib
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
login = "login"
password = "password"
key = "ABC123ABC123ABC1"
Ci = "ABC123ABC123"
Ri = "37c0480063021011988c0095"
Sid = "37c04800630"
id = "37c04800123"

while True:
    # Cria o socket que será usado para a conexão SSL
    serverSocket = socket()
    serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    serverSocket.bind((servidor, porta))

    serverSocket.listen(5)

    # Aguarda a conexão com o cliente
    # print("Servidor aguardando conexão...")
    (clientConnection, clientAddress) = serverSocket.accept()
    # print("Conectado com: ", clientAddress)

    # Cria o socket seguro SSL
    secureClientSocket = ssl.wrap_socket(clientConnection, server_side=True,
                                         certfile="./mycert.pem",
                                         keyfile="./mycert.pem",
                                         ssl_version=ssl.PROTOCOL_TLSv1_2)

    initial_msg = secureClientSocket.recv(1024).decode()
    initial_msg = initial_msg.split(';')

    if initial_msg[0] == 'CONNECT':
        # print('CONNECT')

        if int(initial_msg[1]) in Sid:

            secureClientSocket.close()
            serverSocket.close()

            # Atibue uma nova porta para ser usada na próxima conexão
            novaPorta = 5000

            # Cria o novo socket que será usado nas pŕoximas mensagens
            obj_socket = socket()
            obj_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            obj_socket.bind((servidor, novaPorta))
            obj_socket.listen(5)

            # print("Aguardando cliente...")
            #
            # # Aguarda a conexão com o cliente
            con, cliente = obj_socket.accept()
            # print("Conectado com: ", cliente)

            Ci_to_send = Ci[int(initial_msg[1])]

            # Crifra a mensagem para enviar
            cipher = AES.new(bytes(key[int(initial_msg[1])], 'utf-8'), AES.MODE_ECB)
            Ci_enc = cipher.encrypt(pad(bytes(str(Ci_to_send), 'utf-8'), 16))
            msg = b64encode(Ci_enc)

            con.send(str(msg).encode())

            Ri_enc = con.recv(1024).decode()

            # Descripta a mensagem recebida
            decipher = AES.new(bytes(key[int(initial_msg[1])], 'utf-8'), AES.MODE_ECB)
            Ri_enc = b64decode(Ri_enc[2:-1])
            Ri_dec = unpad(decipher.decrypt(Ri_enc), 16).decode()

            if str(Ri[int(initial_msg[1])]) == str(Ri_dec):
                # print("Ri válido")

                con.send('OK'.encode())

                Hlogin_pass_id_enc = con.recv(1024).decode()

                # Descripta a mensagem recebida
                decipher = AES.new(bytes(key[int(initial_msg[1])], 'utf-8'), AES.MODE_ECB)
                Hlogin_pass_id_enc = b64decode(Hlogin_pass_id_enc[2:-1])
                Hlogin_pass_id_dec = unpad(decipher.decrypt(Hlogin_pass_id_enc), 16).decode()

                Hlogin_password_id = hashlib.sha1((str(id[int(initial_msg[1])]) +
                                                   str(password[int(initial_msg[1])]) +
                                                   str(login[int(initial_msg[1])])).encode()).hexdigest()

                if str(Hlogin_password_id) == str(Hlogin_pass_id_dec):
                    # print("Credenciais válidas")

                    con.send('Authorized'.encode())

            con.close()
            obj_socket.close()
