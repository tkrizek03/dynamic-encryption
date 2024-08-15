import sys
import socket
import os
from Crypto.PublicKey import RSA
from DynamicEncrypterDecrypter import EncrypterDecrypter


if len(sys.argv) < 4:
    msg = input("Please enter message: ")
    serverHost = input("Please enter host IP: ")
    serverPort = int(input("Please enter host port: "))
else:
    msg = sys.argv[1]
    serverHost = sys.argv[2]
    serverPort = int(sys.argv[3])

# Connect to server
try:   
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Trying to connect...")
    clientSocket.connect((serverHost, serverPort))
    print( 'Connection succeeded')
except ConnectionRefusedError as Err:
    print("Connection refused by server.")
    sys.exit(0)
except TimeoutError as Err:
    print("Timeout... Cannot find host server.")
    sys.exit(0)

try:    
    crypto = EncrypterDecrypter()
    crypto.generateKeys("clientPublicKey.pem", "clientPrivateKey.pem")
    crypto.loadKeys("clientPublicKey.pem", "clientPrivateKey.pem")
    clientPublicKey = crypto.publicKey
    clientSocket.send(clientPublicKey.exportKey())
    
    serverPubKey = RSA.importKey(clientSocket.recv(4096))
    print("Received public key from server... Encrypting data.")
except ConnectionResetError as Error:
    os.remove("clientPrivateKey.pem")
    os.remove("clientPublicKey.pem")
    print("The server was forcibly closed by the remote host.")

#Send the data to the server

packet = crypto.encrypt(serverPubKey, msg.encode("utf-8"))
clientSocket.sendall(packet)
print("Packet sent")


# Wait for the echo
try:
    rawEcho = clientSocket.recv(4096)
    print("Decrypting echo...")
    theEcho = crypto.decrypt(rawEcho).decode("utf-8")
    print("Received - %s" % theEcho)
    os.remove("clientPrivateKey.pem")
    os.remove("clientPublicKey.pem")
    clientSocket.close()
    print("Client Socket closed.")
except OSError as ConnectionReset:
    print("Connection closed before receiving response")    
