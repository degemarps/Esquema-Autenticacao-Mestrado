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
key = ''
Login = ''
Password = ''
ID = ''

initial_time = time.time()

# Cria o socket
clientSocket = socket()
clientSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

# Tenta se conectar com o servidor
connected = False
while not connected:
    try:
        clientSocket.connect((servidor, porta))
        connected = True
    except Exception as e:
        pass

clientSocket.send('AUTHENTICATE'.encode())

Ci = clientSocket.recv(1024)

Ri = '37c0480063021011988c0095'
clientSocket.send(Ri.encode())

Sid = clientSocket.recv(1024).decode()

# Fecha as conexões seguras
clientSocket.close()

# Atibue uma nova porta para ser usada na próxima conexão
novaPorta = 4001

obj_socket = socket(AF_INET, SOCK_STREAM)

# Tenta se conectar com o servidor
connected = False
while not connected:
    try:
        obj_socket.connect((servidor, novaPorta))
        connected = True
    except Exception as e:
        pass

# Gera o keyAccess
keyAccess = (str(preLogin) + str(prePass))
keyAccess = hashlib.sha1(str(keyAccess).encode()).hexdigest()
obj_socket.send(str(keyAccess).encode())

# Recebe o Cid do servidor
Cid_recv = obj_socket.recv(1024)
Cid_recv = Cid_recv.decode()
Cid_recv = Cid_recv.split(';')

# Extrai os valores randômicos gerados pelo servidor
Rs1 = int(Cid_recv[0]) ^ int(preLogin, 16)
Rs2 = int(Cid_recv[1]) ^ int(prePass, 16)

Cid = hashlib.sha1((str(preLogin) + str(prePass) + str(Rs1) + str(Rs2)).encode()).hexdigest()

# Verifica se o Cid gerado localmente é igual com o recebido pelo servidor
if Cid_recv[2] == Cid:
    # print("Cid válido")
    obj_socket.send('OK'.encode())

    hello = obj_socket.recv(1024)

    if hello.decode() == 'Hello':
        # Gera novos valores randômicos
        Rc1 = randint(11111111, 99999999)
        Rc2 = randint(11111111, 99999999)

        # Gera os dados necessários para criar o FCid
        FCLog = int(preLogin, 16) ^ Rc1
        FCPass = int(prePass, 16) ^ Rc2
        FCid = hashlib.sha1((str(FCLog) + str(FCPass) + str(Rc1) + str(Rc2)).encode()).hexdigest()

        # Envia o dado para conseguir a autorização do servidor
        # print("Ri: ", Ri)
        # print("Sid: ", Sid)
        AuthH = hashlib.sha1((str(Ri) + Sid).encode()).hexdigest()

        obj_socket.send(str(AuthH).encode())

        ok = obj_socket.recv(1024)

        if ok.decode() == 'OK':
            # print("OK recebido")

            obj_socket.send((str(FCLog) + ';' + str(FCPass) + ';' + str(FCid)).encode())

            Login = (int(preLogin, 16) ^ int(prePass, 16)) ^ (int(Rs1) ^ int(Rs2))
            Password = (int(preLogin, 16) ^ int(prePass, 16)) ^ (int(Rc1) ^ int(Rc2))

            HC = hashlib.sha1((str(Login) + str(Password)).encode()).hexdigest()

            HC_server = obj_socket.recv(1024).decode()

            if HC == str(HC_server):
                # print("HC válido")

                # Início da definição do ID
                Rid = randint(11111111, 99999999)

                ID_init = (int(Login) ^ int(Rid)) ^ int(Password)
                HIid = hashlib.sha1((str(Login) + str(Password) + str(Rid)).encode()).hexdigest()

                obj_socket.send(("OK" + ';' + str(ID_init) + ';' + str(HIid)).encode())

                ID_xor = (int(Login) ^ int(Rid)) ^ (int(Password) ^ int(Rid))

                ID = hashlib.sha1(str(ID_xor).encode()).hexdigest()

                # Início da fase de acordo de chave
                Rkey1 = hex(int.from_bytes(os.urandom(8), byteorder="big"))[2:]

                Init_Key1 = int(preKey, 16) ^ int(Rkey1, 16)
                HC = hashlib.sha1((str(Login) + str(Password) + str(ID)).encode()).hexdigest()
                HInit_Key1 = hashlib.sha1((str(Init_Key1) + str(Rkey1) + str(preKey)).encode()).hexdigest()

                obj_socket.send((str(Init_Key1) + ';' + str(HC) + ';' + str(HInit_Key1)).encode())

                init_key2_3 = obj_socket.recv(1024).decode()
                init_key2_3 = init_key2_3.split(';')

                Rkey2 = int(init_key2_3[0]) ^ int(preKey, 16)
                Rkey3 = int(init_key2_3[1]) ^ int(preKey, 16)

                key_part1 = int(Rkey1, 16) ^ int(Rkey2)
                key_part2 = int(Rkey1, 16) ^ int(Rkey3)

                key = int(key_part1) ^ int(key_part2)

                Hkey = hashlib.sha1(str(key).encode()).hexdigest()

                obj_socket.send(str(Hkey).encode())

                key = hex(key)[2:]

                # print("Ci: ", Ci)
                # print("Ri: ", Ri)
                # print("Sid: ", Sid)
                # print("Login: ", Login)
                # print("Password: ", Password)
                # print("Key: ", key)

            else:
                print("HC inválido")

            obj_socket.close()
        else:
            print("OK não recebido")

    else:
        print("Hello não recebido")
        obj_socket.close()

else:
    print("Cid inválido")
    obj_socket.send('ERRO'.encode())
    obj_socket.close()

# Fecha a conexão
obj_socket.close()

# ----------------------------------------

# Cria o socket que será usado para a conexão SSL
# context = ssl.SSLContext()
# context.verify_mode = ssl.CERT_REQUIRED

# context.load_verify_locations("./mycert.pem")

# context.load_cert_chain(certfile="./mycert.pem", keyfile="./mycert.pem")

# clientSocket = socket()
# clientSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

# # Cria o socket seguro SSL
# secureClientSocket = context.wrap_socket(clientSocket)

# # Tenta se conectar com o servidor
# secureClientSocket.connect((servidor, porta))

# server_cert = secureClientSocket.getpeercert()

# secureClientSocket.send(('CONNECT' + ';' + str(Sid)).encode())

# # Fecha as conexões seguras
# secureClientSocket.close()
# clientSocket.close()

# # time.sleep(10)

# # Atibue uma nova porta para ser usada na próxima conexão
# novaPorta = 5000

# new_socket = socket()
# new_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

# # Tenta se conectar com o servidor
# connected = False
# while not connected:
#     try:
#         new_socket.connect((servidor, novaPorta))
#         connected = True
#     except Exception as e:
#         pass

# Ci_enc = new_socket.recv(1024).decode()

# # Decripta a mensagem recebida
# decipher = AES.new(bytes(key, 'utf-8'), AES.MODE_ECB)
# Ci_enc = b64decode(Ci_enc[2:-1])
# Ci_dec = unpad(decipher.decrypt(Ci_enc), 16).decode()

# if str(Ci_dec) == str(Ci)[2:-1]:
#     # print("Ci recebido")

#     # Encripta a mensagem para enviar
#     cipher = AES.new(bytes(key, 'utf-8'), AES.MODE_ECB)
#     Ri_enc = cipher.encrypt(pad(bytes(str(Ri), 'utf-8'), 16))
#     msg = b64encode(Ri_enc)

#     new_socket.send(str(msg).encode())

#     ok_rec = new_socket.recv(1024).decode()

#     if str(ok_rec) == 'OK':
#         # print('OK recebido')

#         Hlogin_password_id = hashlib.sha1((str(ID) + str(Password) + str(Login)).encode()).hexdigest()

#         # Encripta a mensagem para enviar
#         cipher = AES.new(bytes(key, 'utf-8'), AES.MODE_ECB)
#         Hlogin_pass_id_enc = cipher.encrypt(pad(bytes(str(Hlogin_password_id), 'utf-8'), 16))
#         msg = b64encode(Hlogin_pass_id_enc)

#         new_socket.send(str(msg).encode())

#         auth_rec = new_socket.recv(1024).decode()

#         if str(auth_rec) == 'Authorized':
#             # print('Publicação Autorizada')

#             client = mqtt.Client()
#             client.connect("192.168.30.2", 1883, 60)
#             client.publish("topic/test", "Hello world!")
#             client.disconnect()

# new_socket.close()

# print("--- %.2f seconds ---" % (time.time() - initial_time))

# ----------------------------------------

cont = 0

while cont < 1000:
    # Cria o socket
    clientSocket = socket()
    clientSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

    # Tenta se conectar com o servidor
    clientSocket.connect((servidor, porta))

    clientSocket.send(('CONNECT' + ';' + str(Sid)).encode())

    # Fecha as conexões seguras
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

    Ci_dec = new_socket.recv(1024).decode()

    if str(Ci_dec) == str(Ci)[2:-1]:
        # print("Ci recebido")

        new_socket.send(str(Ri).encode())

        ok_rec = new_socket.recv(1024).decode()

        if str(ok_rec) == 'OK':
            # print('OK recebido')

            Hlogin_password_id = hashlib.sha1((str(ID) + str(Password) + str(Login)).encode()).hexdigest()

            new_socket.send(str(Hlogin_password_id).encode())

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
