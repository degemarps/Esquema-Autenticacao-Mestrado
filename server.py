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
servidor = ''
porta = 4000
preLogin = 'c1fa34b2'
prePass = '12ef567a'
preKey = '2b58934fa02f34f1'
logins = {}
passwords = {}
keys = {}
Cis = {}
Ris = {}
Sids = []
ids = {}

while True:
    # Cria o socket que será usado para a conexão SSL
    serverSocket = socket()
    serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    serverSocket.bind((servidor, porta))

    serverSocket.listen(5)

    # Aguarda a conexão com o cliente
    print("Servidor aguardando conexão...")
    (clientConnection, clientAddress) = serverSocket.accept()
    print("Conectado com: ", clientAddress)

    # Cria o socket seguro SSL
    secureClientSocket = ssl.wrap_socket(clientConnection, server_side=True,
                                         certfile="./mycert.pem",
                                         keyfile="./mycert.pem",
                                         ssl_version=ssl.PROTOCOL_TLSv1_2)

    initial_msg = secureClientSocket.recv(1024).decode()
    initial_msg = initial_msg.split(';')

    if initial_msg[0] == 'CONNECT':
        print('CONNECT')

        if int(initial_msg[1]) in Sids:

            secureClientSocket.close()
            serverSocket.close()

            # Atibue uma nova porta para ser usada na próxima conexão
            novaPorta = 5000

            # Cria o novo socket que será usado nas pŕoximas mensagens
            obj_socket = socket()
            obj_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            obj_socket.bind((servidor, novaPorta))
            obj_socket.listen(5)

            print("Aguardando cliente...")
            #
            # # Aguarda a conexão com o cliente
            con, cliente = obj_socket.accept()
            print("Conectado com: ", cliente)

            Ci_to_send = Cis[int(initial_msg[1])]

            # Crifra a mensagem para enviar
            cipher = AES.new(bytes(keys[int(initial_msg[1])], 'utf-8'), AES.MODE_ECB)
            Ci_enc = cipher.encrypt(pad(bytes(str(Ci_to_send), 'utf-8'), 16))
            msg = b64encode(Ci_enc)

            con.send(str(msg).encode())

            Ri_enc = con.recv(1024).decode()

            # Descripta a mensagem recebida
            decipher = AES.new(bytes(keys[int(initial_msg[1])], 'utf-8'), AES.MODE_ECB)
            Ri_enc = b64decode(Ri_enc[2:-1])
            Ri_dec = unpad(decipher.decrypt(Ri_enc), 16).decode()

            if str(Ris[int(initial_msg[1])]) == str(Ri_dec):
                print("Ri válido")

                con.send('OK'.encode())

                Hlogin_pass_id_enc = con.recv(1024).decode()

                # Descripta a mensagem recebida
                decipher = AES.new(bytes(keys[int(initial_msg[1])], 'utf-8'), AES.MODE_ECB)
                Hlogin_pass_id_enc = b64decode(Hlogin_pass_id_enc[2:-1])
                Hlogin_pass_id_dec = unpad(decipher.decrypt(Hlogin_pass_id_enc), 16).decode()

                Hlogin_password_id = hashlib.sha1((str(ids[int(initial_msg[1])]) +
                                                   str(passwords[int(initial_msg[1])]) +
                                                   str(logins[int(initial_msg[1])])).encode()).hexdigest()

                if str(Hlogin_password_id) == str(Hlogin_pass_id_dec):
                    print("Credenciais válidas")

                    con.send('Authorized'.encode())

            con.close()

    else:

        # Início da comunicação
        Ci = randint(11111111, 99999999)
        secureClientSocket.send(str(Ci).encode())

        Ri = secureClientSocket.recv(1024).decode()

        Sid = randint(11111111, 99999999)
        secureClientSocket.send(str(Sid).encode())

        Sids.append(Sid)
        Cis[Sid] = Ci
        Ris[Sid] = Ri

        # Fecha as conexões
        secureClientSocket.close()
        serverSocket.close()

        # Atibue uma nova porta para ser usada na próxima conexão
        novaPorta = 4001

        while True:
            # Cria o novo socket que será usado nas pŕoximas mensagens
            obj_socket = socket(AF_INET, SOCK_STREAM)
            obj_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            obj_socket.bind((servidor, novaPorta))
            obj_socket.listen(5)

            print("Aguardando cliente...")

            # Aguarda a conexão com o cliente
            con, cliente = obj_socket.accept()
            print("Conectado com: ", cliente)

            # Início da comunicação
            while True:
                keyAccessRec = con.recv(1024)

                # Gera novos valores randômicos
                Rs1 = randint(11111111, 99999999)
                Rs2 = randint(11111111, 99999999)

                CLog = int(preLogin, 16) ^ Rs1
                CPass = int(prePass, 16) ^ Rs2

                Cid = hashlib.sha1((str(preLogin) + str(prePass) + str(Rs1) + str(Rs2)).encode()).hexdigest()

                # Envia o Cid
                con.send((str(CLog) + ';' + str(CPass) + ';' + str(Cid)).encode())

                # Aguarda receber a resposta
                respostaCid = con.recv(1024)

                if respostaCid.decode() == 'OK':
                    con.send('Hello'.encode())

                    AuthH_recv = con.recv(1024).decode()

                    AuthH = hashlib.sha1((str(Ris[Sid]) + str(Sid)).encode()).hexdigest()

                    if AuthH_recv == AuthH:
                        # print("AuthH válido")

                        con.send('OK'.encode())

                        data_recv = con.recv(1024).decode()
                        data_recv = data_recv.split(';')

                        Rc1 = int(data_recv[0]) ^ int(preLogin, 16)
                        Rc2 = int(data_recv[1]) ^ int(prePass, 16)

                        FCid = hashlib.sha1((str(data_recv[0])
                                             + str(data_recv[1])
                                             + str(Rc1)
                                             + str(Rc2)).encode()).hexdigest()

                        if FCid == str(data_recv[2]):
                            # print("FCid validado!")

                            Login = (int(preLogin, 16) ^ int(prePass, 16)) ^ (int(Rs1) ^ int(Rs2))
                            Password = (int(preLogin, 16) ^ int(prePass, 16)) ^ (int(Rc1) ^ int(Rc2))

                            HC = hashlib.sha1((str(Login) + str(Password)).encode()).hexdigest()

                            con.send(str(HC).encode())

                            # Início da definição do ID
                            init_ID = con.recv(1024).decode()
                            init_ID = init_ID.split(';')

                            if str(init_ID[0]) == "OK":
                                # print("HC válido e início da definição do ID")

                                logins[Sid] = Login
                                passwords[Sid] = Password

                                Rid = (int(init_ID[1]) ^ Password) ^ int(Login)

                                HIid = hashlib.sha1((str(Login) + str(Password) + str(Rid)).encode()).hexdigest()

                                if HIid == str(init_ID[2]):
                                    ID_xor = (int(Login) ^ int(Rid)) ^ (int(Password) ^ int(Rid))

                                    ID = hashlib.sha1(str(ID_xor).encode()).hexdigest()

                                    ids[Sid] = ID

                                    # Início da fase de acordo de chave
                                    init_key1 = con.recv(1024).decode()
                                    init_key1 = init_key1.split(';')

                                    Rkey1 = int(init_key1[0]) ^ int(preKey, 16)

                                    HC = hashlib.sha1((str(Login) + str(Password) + str(ID)).encode()).hexdigest()

                                    HInit_Key1 = hashlib.sha1((str(init_key1[0])
                                                               + str(hex(Rkey1)[2:])
                                                               + str(preKey)).encode()).hexdigest()

                                    if HC == init_key1[1] and HInit_Key1 == init_key1[2]:
                                        # print("Parte 1 do acordo de chave feito")

                                        Rkey2 = hex(int.from_bytes(os.urandom(8), byteorder="big"))[2:]
                                        Rkey3 = hex(int.from_bytes(os.urandom(8), byteorder="big"))[2:]

                                        Init_Key2 = int(preKey, 16) ^ int(Rkey2, 16)
                                        Init_Key3 = int(preKey, 16) ^ int(Rkey3, 16)

                                        HInit_Key2 = hashlib.sha1((str(Init_Key2)
                                                                   + str(Init_Key3)
                                                                   + str(Rkey2)
                                                                   + str(Rkey3)).encode()).hexdigest()

                                        con.send((str(Init_Key2) + ';' + str(Init_Key3) + ';' + str(HInit_Key2)).encode())

                                        key_part1 = int(Rkey1) ^ int(Rkey2, 16)
                                        key_part2 = int(Rkey1) ^ int(Rkey3, 16)

                                        key = int(key_part1) ^ int(key_part2)

                                        if len(str(key)) < 16:
                                            key = str(key) + 'f'

                                        Hkey = hashlib.sha1(str(key).encode()).hexdigest()

                                        Hkey_recv = con.recv(1024).decode()

                                        if str(Hkey_recv) == Hkey:
                                            # print("Chave de criptografia validada")
                                            keys[Sid] = hex(key)[2:]

                                            print("Cis: ", Cis)
                                            print("Ris: ", Ris)
                                            print("Sids: ", Sids)
                                            print("Logins: ", logins)
                                            print("Passwords: ", passwords)
                                            print("Keys: ", keys)
                                            print()

                                            con.close()

                                            # data = con.recv(1024).decode()
                                            #
                                            # decipher = AES.new(bytes(keys[Sid], 'utf-8'), AES.MODE_ECB)
                                            #
                                            # data = b64decode(data[2:-1])
                                            #
                                            # print(unpad(decipher.decrypt(data), 16).decode('utf-8'))

                                        else:
                                            print("Chave de criptografia não validada")
                                            con.close()

                                    else:
                                        print("Error na parte 1 do acordo de chave")
                                        con.close()

                                else:
                                    print("HIid não validado")
                                    con.close()

                        else:
                            print("FCid invalidado!")
                            con.close()

                        con.close()
                        break
                    else:
                        print("AuthH inválido")
                        con.close()
                        break
                else:
                    con.close()
                    break

            # Fecha a conexão
            con.close()
            break
