import sys
import base64
import hashlib
import argparse

DEFAULT_SALT_LENGTH = 8

def none2empty(array):
    return [x if x != None else "" for x in array] 

def generate_password(passphrase, username=None, resourcename=None, salt=None, saltlength = DEFAULT_SALT_LENGTH):

    #(passphrase, username, resourcename, salt) = none2empty((passphrase, username, resourcename, salt))
    

    

    hctx = hashlib.sha256()
    hctx.update(passphrase.encode('utf-8'))

    if username != None:
        hctx.update(username.encode('utf-8'))
    if resourcename != None:
        hctx.update(resourcename.encode('utf-8'))

    #print(salt)
    if salt != None:
        si = int(salt, 16)
        salt_b = si.to_bytes(saltlength, byteorder = "big")
        hctx.update(salt_b)
        #print(salt_b)

    h = hctx.digest()
    return h

    
    

def result2str(r, signs_in_row = None, altchars='!.'):

    if type(altchars) == str:
        altchars = altchars.encode("utf-8")
    b64 = base64.b64encode(r,altchars).decode("utf-8")
    #print(b64)
    #print(type(b64))
   
    if(signs_in_row ==0):
        return b64
    else:
        rows = [b64[i:signs_in_row+i] for i in range(0, len(b64), signs_in_row)]
  #      print (rows)
  #      print (type(rows[0]))
        return "".join(str(x)  +"\n" for x in rows)
        

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    #parser.add_argument("-g", "--guided", help="Guided interface, disables: -p, -u, -s, -a",
    #                dest="guided", action="store_true")
    
    parser.add_argument("-p", "--passphrase", help="Specify passphrase",
                    dest="passphrase", default = None)
    parser.add_argument("-u", "--username", help="Specify username",
                    dest="username", default = None)
    parser.add_argument("-r", "--resource", help="Specify resource name e.g. gmail.com",
                    dest="resourcename", default = None)
    parser.add_argument("-s", "--salt", help="Specify salt in hex e.g 0x01020304 (in big endian)",
                    dest="salt", default = None)
    parser.add_argument("-a", "--altchars", help="Specify alternative chars for '+' and '/'",
                    dest="altchars", default = None)
    parser.add_argument("-l", "--linelength", help="Specify the number of characters in row",
                    dest="linelength", default = None, type=int)
    parser.add_argument("-S", "--saltlength", help="Specify the number of bytes in salt",
                    dest="saltlength", default = DEFAULT_SALT_LENGTH, type=int)

    args=parser.parse_args()
    #print(args.passphrase)
    
    dgst = generate_password(args.passphrase, args.username, args.resourcename,\
                               args.salt, args.saltlength)
    result = result2str(dgst, args.saltlength,  args.altchars)
    print(result)
