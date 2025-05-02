import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import socket
from scapy.all import *  #no
import ssl
import warnings
import sys
import select
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os

parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

#it may not work at the moment, i havent tested it yet. im in a hurry because my shift starts soon
# i know -- i am not currently using the shared secret to encrypt communication, that is to be implemented next

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    clientSocket =  None

    mode = input("choose mode: 1.receive connection; 2. connect ")

    if mode == "1":
        clientSocket, clientAddress, derivedKey = awaitConnection(s)
    elif mode == "2":
        serverAddress = input("ip address: ")
        derivedKey = connectToServer(serverAddress, s)

    while True:

        print("can now communicate")

        readable, _, _= select.select([clientSocket, sys.stdin], _, _)
        for source in readable:
            if source is clientSocket:
                try:
                    data = clientSocket.recv(1024)
                    if not data:
                        print("Connection closed by peer")
                        clientSocket.close()
                        return
                    print(f"\nReceived: {data.decode('utf-8')}")
                except:
                    print("Error receiving data")
                    clientSocket.close()
                    return
            else:
                msg = input().strip()
                if msg.lower() == "exit":
                    print("Closing connection...")
                    clientSocket.close()
                    return
                
                try:
                    clientSocket.send(msg.encode('utf-8'))
                except:
                    print("Error sending data")
                    clientSocket.close()
                    return
            

    return 0
    
def awaitConnection(s):
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", 443))
        s.listen(5)
        print("listening for connection")
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        while True:
            clientSocket, clientAddress = s.accept()
            
            if clientAddress is not None:
                acceptConnection = input(f"accept connection from {clientAddress}? y/n")
                
                if acceptConnection != "y":
                    print("connection denined")
                    clientSocket.close()
                    continue
                else:

                    print("performing the key exchange...")

                    serverPrivateKey = parameters.generate_private_key()
                    serverPublicKey = serverPrivateKey.public_key()

                    pubKeyBytes = serverPublicKey.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    clientSocket.sendall(pubKeyBytes)

                    clientPubKeyBytes = clientSocket.recv(4096)
                    clientPublicKey = serialization.load_pem_public_key(
                        clientPubKeyBytes,
                        backend=default_backend()
                    )

                    sharedKey = serverPrivateKey.exchange(clientPublicKey)
                    

                    derivedKey = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b'secure_chat_app',
                    ).derive(sharedKey)

                    print("coonection accepted, common secret established")
                    return (clientSocket, clientAddress, derivedKey)

    except KeyboardInterrupt:
        print("\nserver shutting down...")
        return None
    except Exception as e:
        print(e)
        return None
        

def connectToServer(serverIP, s):
    try:
        sslSocket = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLS)

        sslSocket.connect((serverIP, 443))

        serverPubKeyBytes = s.recv(4096)
        serverPublicKey = serialization.load_pem_public_key(serverPubKeyBytes, backend=default_backend())
        
        clientPrivateKey = parameters.generate_private_key()
        clientPublicKey = clientPrivateKey.public_key()

        s.sendall(clientPublicKey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))

        sharedKey = clientPrivateKey.exchange(serverPublicKey)
        derivedKey = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'secure_chat_app',
        ).derive(sharedKey)

        print("Key exchange successful!")

        return derivedKey
    except Exception as e:
        print(f"Connection failed: {e}")
        if 's' in locals():
            s.close()
        return None





if __name__ == "__main__":
    main()





# while True:
#     readable, writable, error = select.select([s], [sys.stdin], [])

#     for read in readable:
#         if read is s:
#             print(s.recv(1000).decode("utf8"))
#         else:
#             msg = sys.stdin.readline()
#             if msg == "exit":
#                 s.close()
#                 exit()
#             s.send(msg.encode("utf8"))



