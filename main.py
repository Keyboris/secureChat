import socket
import select
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

#nat traversal is next to implement

parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

#it may not work at the moment, i havent tested it yet. im in a hurry because my shift starts soon
# i know -- i am not currently using the shared secret to encrypt communication, that is to be implemented next

def main():
    print("Initiating DH parameters...")
    
    #generate own dh parameters 
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())  #sometimes takes a super long time to generate, must be generated twice but only one set is used 
                                                                                                #for communication, the other one gets dropped

    params_bytes = parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3
    )
    
    #create udp socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 8192)
    
    print("Ready")

    mode = input("Choose mode: 1. Receive connection; 2. Connect: ")

    if mode == "1":
        await_connection(s, parameters, params_bytes, 8443)
    elif mode == "2":
        server_address = input("IP address: ")
        connect_to_server(server_address, s, parameters, params_bytes, 8443)

def await_connection(s, parameters, params_bytes, port):
    try:
        s.bind(("0.0.0.0", port))
        print(f"Waiting for connection on port {port}...")
        
        #first receive: clients parameters or "USING_YOURS"
        client_message, client_address = s.recvfrom(4096)
        
        #determine if well use our parameters or the clients
        if client_message == b"USING_YOURS":
            #client will use our parameters
            s.sendto(params_bytes, client_address)
            params_to_use = parameters
            print("Client is using our DH parameters")
        else:
            #well use clients parameters
            params_to_use = serialization.load_pem_parameters(
                client_message,
                backend=default_backend()
            )
            s.sendto(b"RECEIVED_PARAMS", client_address)
            print("Using client's DH parameters")
        
        #receive clients public key
        client_pub_key_bytes, _ = s.recvfrom(4096)
        print(f"Connection from {client_address}")
        
        accept = input("Accept connection? (y/n): ")
        if accept.lower() != 'y':
            s.sendto(b"REJECT", client_address)
            return
            
        #generate our keys using the agreed parameters
        private_key = params_to_use.generate_private_key()
        public_key = private_key.public_key()
        
        #send our public key
        pub_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        s.sendto(pub_key_bytes, client_address)
        
        #load clients public key
        client_public_key = serialization.load_pem_public_key(
            client_pub_key_bytes,
            backend=default_backend()
        )
        
        #compute shared key
        try:
            shared_key = private_key.exchange(client_public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,  #maybe use some uniform salt for both parties in the future? can salt be translated through unsecured channel?
                info=b'secure_chat_app',
            ).derive(shared_key)
            print("Shared secret established!")
            communicate(s, client_address, derived_key)
        except Exception as e:
            print(f"Key exchange failed: {e}")
            s.sendto(b"KEY_ERROR", client_address)

    except Exception as e:
        print(f"Error: {e}")
    finally:
        s.close()

def connect_to_server(server_ip, s, parameters, params_bytes, port):
    try:
        #decide randomly whether to use our parameters or ask for servers
        #some dude on stack overflow said that it is a more secure way than always using ours/their
        use_own_params = os.urandom(1)[0] % 2 == 0
        
        if use_own_params:
            #send our parameters
            s.sendto(params_bytes, (server_ip, port))
            params_to_use = parameters
            print("Using our DH parameters")
            
            #wait for acknowledgement
            response, _ = s.recvfrom(4096)
            if response != b"RECEIVED_PARAMS":
                print("Server didn't acknowledge parameters")
                return
        else:
            #request server's parameters
            s.sendto(b"USING_YOURS", (server_ip, port))
            print("Requesting server's DH parameters")
            
            #receive server's parameters
            server_params_bytes, _ = s.recvfrom(4096)
            params_to_use = serialization.load_pem_parameters(
                server_params_bytes,
                backend=default_backend()
            )
            print("Received server's parameters")
        
        #generate our keys using the agreed parameters
        private_key = params_to_use.generate_private_key()
        public_key = private_key.public_key()
        
        #send our public key
        pub_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        s.sendto(pub_key_bytes, (server_ip, port))
        
        #receive servers response
        data, server_address = s.recvfrom(4096)
        
        if data == b"REJECT":
            print("Connection rejected by server")
            return
        elif data == b"KEY_ERROR":
            print("Key exchange failed on server side")
            return
            
        #load servers public key
        server_public_key = serialization.load_pem_public_key(
            data,
            backend=default_backend()
        )
        
        #compute shared key
        try:
            shared_key = private_key.exchange(server_public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'secure_chat_app',
            ).derive(shared_key)
            print("Shared secret established!")
            communicate(s, server_address, derived_key)
        except Exception as e:
            print(f"Key exchange failed: {e}")

    except Exception as e:
        print(f"Connection failed: {e}")
    finally:
        s.close()

def communicate(s, peer_address, derived_key):

    def encrypt_message(message, key):
        iv = os.urandom(16)

        padder = padding.PKCS7(128).padder()
        padded_message = padder.update(message) + padder.finalize()

        encryptor = Cipher(algorithm = algorithms.AES(key), mode = modes.CBC(iv), backend = default_backend()).encryptor()

        encrypted_message = encryptor.update(padded_message) + encryptor.finalize()  #cbc is crying because the message length is not the multiple of the block size
        return iv + encrypted_message

    def decrypt_message(payload, key):
        iv = payload[:16]
        encrypted_message = payload[16:]

        decryptor = Cipher(algorithm = algorithms.AES(key), mode = modes.CBC(iv), backend = default_backend()).decryptor()

        padded_plaintext = decryptor.update(encrypted_message) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        unpadded_plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return unpadded_plaintext



    print("You can now communicate (type 'exit' to quit)")
    
    while True:
        readable, _, _ = select.select([s, sys.stdin], [], [])
        
        for source in readable:
            if source is s:
                data, addr = s.recvfrom(4096)
                if addr == peer_address:
                    try:
                        plaintext = decrypt_message(data, derived_key)
                        print(f"\nReceived: {plaintext.decode('utf-8')}")
                    except Exception as e:
                        print(f"\nFailed to decrypt message: {e}")

                        print(f"message received: {data}")

            else:
                msg = input().strip()
                if msg.lower() == "exit":
                    print("Closing connection...")
                    return
                s.sendto(encrypt_message(msg.encode('utf-8'), derived_key), peer_address)

if __name__ == "__main__":
    main()
