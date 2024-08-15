import sys
import struct
import os
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

'''
The EncrypterDecrypter class in this file supports simple asymetric 
private and public key encryption.  The code is heavily dependent 
upon the pycryptodome project.  Documentation can be found at - 

    https://www.pycryptodome.org/src/api

Note that to use the classes contained in this source you must add
support for pycryptodome by running

    pip install pycryptodome

    SPYDER Note - pip should be run from a SPYDER in app console
    
    The general usage of this is as follows
    
        from EncrypterDecrypter import *
        crypto = EncrypterDecrypter()
        crypto.loadKeys( "publickey.pem", "privatekey.pem" )
        testData = 'This text is very private and needs to be encrypted'
        packet = crypto.encrypt( testData.encode("utf-8") )
        unencryptedTestData = crypto.decrypt(packet).decode("utf-8") )
        if unencryptedTestData != testData:
            print('Encrypt/ Decrypt failed')
        else:
            print('SUCCESS')        

    Note that you can run this file to test the the library is working 
    because it has a main at the bottom that is the code  sample above
'''

class EncrypterDecrypter:
    
    def __init__(self):
        self.privateKeyDestinationFileName = None
        self.publicKeyDestinationFileName = None
        self.privateKey = None
        self.publicKey = None
        
        
    def generateKeys( self, publicKeyDestinationFileName, privateKeyDestinationFileName ):
        self.privateKeyDestinationFileName = privateKeyDestinationFileName
        self.publicKeyDestinationFileName = publicKeyDestinationFileName
        
        self.privateKey = RSA.generate(2048)
        serializedPrivateKey = self.privateKey.export_key()
        with open(privateKeyDestinationFileName, "wb") as f:
            f.write(serializedPrivateKey)
        
        self.publicKey = self.privateKey.publickey()
        serializedPublicKey = self.publicKey.export_key()
        with open(publicKeyDestinationFileName, "wb") as f:
            f.write(serializedPublicKey)
        
    
    def loadKeys( self, publicKeyFileName, privateKeyFileName=None ):
        if os.path.exists( publicKeyFileName ) :
            self.publicKey = RSA.import_key(open(publicKeyFileName).read())
        else:
            raise FileNotFoundError( "The public key file %s does not exist" % publicKeyFileName )
        if privateKeyFileName is not None:
            if os.path.exists( privateKeyFileName ) :
                self.privateKey = RSA.import_key(open(privateKeyFileName).read())
            else:
                raise FileNotFoundError( "The private key file %s does not exist" % publicKeyFileName )
            
    def packBytes( self, aByteArray, someBytes ):
        aByteArray.extend( struct.pack("<h", len( someBytes )) )
        aByteArray.extend(someBytes)
                
        
    def encrypt( self, key, data):
        public_key = key
        session_key = get_random_bytes(16)
        cipher_rsa = PKCS1_OAEP.new(public_key)
        enc_session_key = cipher_rsa.encrypt(session_key)
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        ba = bytearray()
        self.packBytes( ba, enc_session_key )
        self.packBytes( ba, cipher_aes.nonce )
        self.packBytes( ba, tag )
        self.packBytes( ba, ciphertext )
        return ba


    def unpackBytes( self, aByteArray, startIndex ):
        endIndex = startIndex+2
        size = struct.unpack( '<h', aByteArray[startIndex:endIndex] )[0]
        startIndex = endIndex
        endIndex = startIndex + size
        return (aByteArray[startIndex: endIndex], endIndex)


    def decrypt( self, packet ):
        private_key = self.privateKey
        curIndex = 0
        (enc_session_key, curIndex) = self.unpackBytes( packet, curIndex )
        (nonce, curIndex) = self.unpackBytes( packet, curIndex )
        (tag, curIndex) = self.unpackBytes( packet, curIndex )
        (ciphertext, curIndex) = self.unpackBytes( packet, curIndex )                        
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return data            
                    
                    
if __name__ == "__main__":
    print( 'Allocating an EncrypterDecrypter instance' )
    crypto = EncrypterDecrypter()
    
    print( 'Loading publickey.pem and privatekey.pem' )
    crypto.loadKeys( "publickey.pem", "privatekey.pem" )
    
    testdata = 'This text is very private and needs to be encrypted'
    print( 'Encrypting --> [%s]' % testdata )
    packet = crypto.encrypt( testdata.encode("utf-8") )
    print( 'The encrypted data is - \n' )
    print( packet )
    
    print()
    print( 'Decrypting ...' )
    print( '   --> [%s]' % crypto.decrypt(packet).decode("utf-8") )
    print( 'DONE' )
    