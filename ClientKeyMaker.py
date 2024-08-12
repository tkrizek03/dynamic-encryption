import sys
import os
from EncrypterDecrypter import *

usage = '''

This program generates a private and a public key and writes them to two separate files 
named 'publickey.pem' and 'privatekey.pem' by default.  However you can override both
by specifying two arguments on the command line as shown here ... 

     python makePrivatePublicKeys.py  PRIVATE-key-file-name  PUBLIC-key-file-name

Note that if those files already exist the program will report an error and exist.  You
must manually delete any existing files with the default names or provided names before
this program will run

'''

privateKeyFileName = 'privatekey.pem'
publicKeyFileName = 'publickey.pem'
if len(sys.argv) > 1:
    if len(sys.argv[1]) != 3:
        print(usage)
        sys.exit(1)
    else:
        privateKeyFileName = sys.argv[1].strip()
        privateKeyFileName = sys.argv[2].strip()

if os.path.exists( privateKeyFileName ) or os.path.exists( publicKeyFileName ):
    print('\nERROR --> private and/or public key file already exists')
    print( usage )
    sys.exit(1)

try:
    EncrypterDecrypter().generateKeys( publicKeyFileName, privateKeyFileName )
except:
    pass
if (False == os.path.exists( privateKeyFileName )) or (False == os.path.exists( publicKeyFileName )):
    print( '\nERROR --> Failed to create private and/or public key files')
    sys.exit(1)
