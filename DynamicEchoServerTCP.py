import sys
import socket
import os
from Crypto.PublicKey import RSA
from DynamicEncrypterDecrypter import EncrypterDecrypter

crypto = EncrypterDecrypter()
crypto.generateKeys("serverPublicKey.pem", "serverPrivateKey.pem")
crypto.loadKeys("serverPublicKey.pem", "serverPrivateKey.pem")
serverPublicKey = crypto.publicKey

class EchoServerTCP():
    
    #####################################################################
    def __init__( self, ip='127.0.0.1', port=9000 ):
        self.listenFilter = ip
        self.listenPort = port
        self.connections = 0
        self.echoCount = 0
    
    def stats( self ):
        return ( self.connections, self.echoCount )
        
    #####################################################################        
    def run( self ):

        listenSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("Listen socket created")

        try:
            listenSocket.bind( (self.listenFilter, self.listenPort) )
        except OSError as bindException :
            print( "failed to bind to port %d" % self.listenPort )
            print(bindException)
            sys.exit(0)
        print 
        listenSocket.listen(5)
        
        dead = False
        while not dead:
            clientSocket, clientAddress = listenSocket.accept()
            print( "Received connection from ", end='' )
            print( clientAddress )
            self.connections += 1
            clientConnected=True    
            while clientConnected and not dead :
                try:
                    clientPubKey = RSA.importKey(clientSocket.recv(4096))
                    print("Received public key from client.")
                    
                    crypto.generateKeys("serverPublicKey.pem", "serverPrivateKey.pem")
                    crypto.loadKeys("serverPublicKey.pem", "serverPrivateKey.pem")
                    serverPublicKey = crypto.publicKey
                    clientSocket.send(serverPublicKey.exportKey())
                    
                    packet = clientSocket.recv( 4096 )
                    print("Decrypting packet...")
                    msg = crypto.decrypt(packet).decode("utf-8")
                    
                except ConnectionResetError as resetErr:
                    print("Received Connection Reset Error")
                    packet = None
                if not packet:
                    print( "The client has disconnected" )
                    try:
                        clientSocket.close()
                    except OSError:
                        pass                
                    clientConnected = False
                else:
                    print( "Received [%s]" % msg )
                    print("Encrypting echo...")
                    returnData = crypto.encrypt(clientPubKey, msg.encode("utf-8") )
                    clientSocket.sendall( returnData )
                    print("Sent echo")
                    clientConnected = False
                    self.echoCount += 1
                    if msg.lower() == 'die':
                        dead = True
                        os.remove("serverPrivateKey.pem")
                        os.remove("serverPublicKey.pem")
                        if os.path.isfile("clientPublicKey.pem") == True:
                            os.remove("clientPublicKey.pem")

            clientSocket.close()
            
        listenSocket.close()
        print('Shutting echo server down')
        
if len(sys.argv) == 3:
    serverPort = int(sys.argv[2])
    serverHost = sys.argv[1]
else:
    serverHost = "127.0.0.1"
    serverPort = 9000

server = EchoServerTCP(serverHost, serverPort)
server.run()
