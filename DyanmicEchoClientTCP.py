import sys
import socket
import time
from EncrypterDecrypter import *

crypto = EncrypterDecrypter()
crypto.loadKeys( "publickey.pem", "privatekey.pem" )

if len(sys.argv) < 4:
    msg = input("Please enter message: ")
    serverHost = input("Please enter host IP: ")
    serverPort = int(input("Please enter host port: "))
else:
    msg = sys.argv[1]
    serverHost = sys.argv[2]
    serverPort = int(sys.argv[3])

print("Encrypting message...")
packet = crypto.encrypt( msg.encode("utf-8") )

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
    
#Send the data to the server

clientSocket.sendall(packet)
print("Packet sent")

# Wait for the echo
try:
    rawEcho = clientSocket.recv(4096)
    print("Decrypting echo...")
    theEcho = crypto.decrypt(rawEcho).decode("utf-8")
    print("Received - %s" % theEcho)
    clientSocket.close()
    print("Client Socket Closed")
except OSError as ConnectionReset:
    print("Connection closed before receiving response")    
