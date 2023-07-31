from django.shortcuts import render
import random
import os
import base64
from PIL import Image
from io import BytesIO
import  shutil
import numpy as np
#Declaring Permutation table(P), Substitution table(Q) and binary to decimal table
pi_Q = {0: 9, 1: 14, 2: 5, 3: 6, 4: 10, 5: 2, 6: 3, 7: 12, 8: 15, 9: 0, 10: 4, 11: 13, 12: 7, 13: 11, 14: 1, 15: 8}
pi_P = {0: 3, 1: 15, 2: 14, 3: 0, 4: 5, 5: 4, 6: 11, 7: 12, 8: 13, 9: 10, 10: 9, 11: 6, 12: 7, 13: 8, 14: 2, 15: 1,}
hex_to_bin = {'0': "0000", '1': "0001", '2': "0010", '3': "0011", '4': "0100", '5': "0101", '6': "0110", '7': "0111", '8': "1000", '9': "1001", 'a': "1010", 'b': "1011", 'c': "1100", 'd': "1101", 'e': "1110", 'f': "1111"}
bin_to_hex = {"0000": '0', "0001": '1', "0010": '2', "0011": '3', "0100": '4', "0101": '5', "0110": '6', "0111": '7', "1000": '8', "1001": '9', "1010": 'a', "1011": 'b', "1100": 'c', "1101": 'd', "1110": 'e', "1111": 'f'}
bin_to_dec = {0: "0000", 1: "0001", 2: "0010", 3: "0011", 4: "0100", 5: "0101", 6: "0110", 7: "0111", 8: "1000", 9: "1001", 10: "1010", 11: "1011", 12: "1100", 13: "1101", 14: "1110", 15: "1111"}

#Function for initial key generation
#input: -None- output:128 bit Encryption and decryption keys
def kcbingenerator():
    l = []
    for i in range(10):
        l.append(str(i))
    for i in range(97, 103):
        l.append(chr(i))
    key = ""
    for i in range(32):
        a = random.randint(0, len(l)-1)
        key += l[a]
    l0 = key[:16]                           # L0
    r0 = key[16:]                           # R0
    binkey = ''                             # Binary Cipher Key
    for i in r0:
        binkey += hex_to_bin[i]
    crr = ""
    crl = ""
    for i in binkey:
        if(i == '0'):
            crr += '1'
            crl += '1'
        else:
            crr += '0'
            crl += '1'
    Kcbin = binkey+crr                      # Kc Encryption Key in Binary
    Ksbin = crl+crr                         # Ks Decryption Key to be sent Binary
    Kc = ""                                 # Kc Hexadecimal
    for i in range(0, len(Kcbin), 4):
        b = Kcbin[i:i+4]
        Kc += bin_to_hex[b]
    Ks = ""                                 # Ks hexadecimal
    for i in range(0, len(Ksbin), 4):
        b = Ksbin[i:i+4]
        Ks += bin_to_hex[b]
    print();print("Random Cipher Key Used: ", key)
    return Kcbin,Ksbin, key

#A function for xor operation of 4 binary strings
#input:4 32-bit binary strings output:Xor-ed 32-bit binary string
def xor(a,b,c,d):
    r=''
    for i in range(32):
        r+=str(int(a[i])^int(b[i])^int(c[i])^int(d[i]))
    return r

#A function for xor operation of 2 binary strings
#input:2 64-bit binary strings output:Xor-ed 64-bit binary string
def xor2(a,b):
    r=''
    for i in range(len(a)):
        r+=str(int(a[i])^int(b[i]))
    return r

#A function to perform xnor operation 
#input:2 binary string output:xnor-ed output binary string
def xnor(a,b):
    c = xor2(a,b)
    d=''
    for i in c:
        if(i=='0'):
            d+='1'
        else:
            d+='0'
    return d

#A function for performing shift rows operation on a given binary string
#input:16 bit binary string output:16-bit binary string with left circular shift on every 4 bits
def shiftrows(l):
    bigst = ''
    for i in range(0, 16, 4):
        temp = l[i]
        j = i+1
        st = ''
        while(j < i+4):
            st = st+l[j]
            j = j+1
        st = st+temp
        bigst = bigst+st
    return bigst

#A function for performing substitution using Q table on given binary string
#input:32-bit binary string output:binary string after performing substitution
def substitutionQ(pt):
    re = ""
    k = int(pt, 2)
    re += bin_to_dec[pi_Q[k]]
    return re

#A function for performing substitution using P table on given binary string
#input:32-bit binary string output:binary string after performing substitution
def substitutionP(pt):
    re = ""
    k = int(pt, 2)
    re += bin_to_dec[pi_P[k]]
    return re

#A function involving 3 iterations with a combination of substitution using P andsubstitution using Q tables
#input:16-bit binary string output:16-bit binary string after performing all necessary subtitution operations
def Ffunction(p):
    for i in range(3):
        res=''
        for j in range(0,16,4):
            if(j%8==0):
                if(i!=1):
                    res+=substitutionP(p[j:j+4])
                else:
                    res+=substitutionQ(p[j:j+4])
            else:
                if(i!=1):
                    res+=substitutionQ(p[j:j+4])
                else:
                    res+=substitutionP(p[j:j+4])
        t1 = res[0:4]
        t2 = res[4:8]
        t3 = res[8:12]
        t4 = res[12:16]
        if(i!=2):
            T11 = t1[:2]+t2[:2]
            T21 = t1[2:]+t3[:2]
            T31 = t2[2:]+t4[:2]
            T41 = t3[2:]+t4[2:]
            p = T11+T21+T31+T41
        else:
            p = res
    return p

#A function for performing railfence operation
#input:Binary string on which railfence is to be performed output:binary string with same length as the input string after performing railfence cipher with key length 2
def railfence(text):
    key=2
    fence = [[None] * len(text) for i in range(key)]
    rails = list(range(key - 1)) + list(range(key - 1, 0, -1))
    for i, char in enumerate(text):
        fence[rails[i % len(rails)]][i] = char
    result = []
    for rail in fence:
        result += [char for char in rail if char is not None]
    return ''.join(result)

#A function to perform transposition cipher by converting the input to matrix and transpose it. 
#16-bit binary string output:binary string after performing transpose and converting it to string
def transposition(p):
    matrix = [[p[i+j*4] for i in range(4)] for j in range(4)]
    trans=''
    for i in range(4):
        l=''
        for j in range(4):
            l+=matrix[j][i]
        trans+=l
    return trans

#A function to produce 5 round keys for a given 128 bit key (both for encryption and decryption)
#input:128-bit key in binary string format output:List of 5 binary strings each 32-bit long
def keygenerator(kc):
    keys = []
    for i in range(0, 128, 16):
        k = kc[i:i+16]
        keys.append(k)
    
    for i in range(len(keys)):
        keys[i] = shiftrows(keys[i])
    
    ffunced = []
    for i in keys:
        ffunced.append(Ffunction(i))
    
    tranrail=[]
    for i in range(8):
        if(i in [1,2,5,6]):
            tranrail.append(railfence(ffunced[i]))
        else:
            tranrail.append(transposition(ffunced[i]))
    FinalKeys=[]
    for i in range(0,8,2):
        l=''
        l=tranrail[i]+tranrail[i+1]
        FinalKeys.append(l)
    key5 = xor(FinalKeys[0],FinalKeys[1],FinalKeys[2],FinalKeys[3])
    FinalKeys.append(key5)
    return FinalKeys

#Padding function to match the input to be able to divide by 128-bit blocks
#input: random binary string of any length output: Padded binary string which is divisible by 128
def padding(binval):
    padded=[]
    if(len(binval)<128):
        x = 128-len(binval)
        newbinval = binval+'0'*x
        padded.append(newbinval)
    elif(len(binval)==128):
        padded.append(binval)
    else:
        if(len(binval)%128==0):
            for j in range(0,len(binval),128):
                t = binval[j:j+128]
                padded.append(t)
        else:
            z = len(binval)%128
            rem = 128-z
            binval = binval+'0'*rem
            for j in range(0,len(binval),128):
                t = binval[j:j+128]
                padded.append(t)
    return padded

#A function for generating initial key generation for decryption key
#input: 128-bit decryption key produced by initial key generationn function output:128-bit key binary string used for key generation process 
def decryptionkey(x):
    l0 = x[:64]
    r0 = x[64:]
    k1 = xor2(l0,r0)
    dec_key = r0+k1
    return dec_key

#This function is used to reorder the decryption round keys obtained in such a way that they are in reverse order of encryption round keys
def decryptionkeygenerator(key):
    DecKeys = keygenerator(key)
    DecryptionRoundKeys = []
    DecryptionRoundKeys.append(DecKeys[4])
    DecryptionRoundKeys.append(DecKeys[0])
    DecryptionRoundKeys.append(DecKeys[3])
    DecryptionRoundKeys.append(DecKeys[2])
    DecryptionRoundKeys.append(DecKeys[1])
    return DecryptionRoundKeys

#Encryption function of one round 
#input:128-bit binary data of plaintext, Number of the round output: Ciphertext of the corresponding plaintext
def encryption(pt,j, EncryptionRoundKeys):
    P = []
    Cipher = ''
    for i in range(0,len(pt),32):
        P.append(pt[i:i+32])
    R011 = xnor(P[0],EncryptionRoundKeys[j])
    C1 = R011 #Cipher 1
    EFL1 = Ffunction(R011[:16])+Ffunction(R011[16:])
    Cipher+=R011
    R014 = xnor(P[3],EncryptionRoundKeys[j])
    C4 = R014 #Cipher 4
    EFR1 = Ffunction(R014[:16])+Ffunction(R014[16:])
    C2 = xor2(EFL1,P[2])
    Cipher+=C2
    C3 = xor2(EFR1,P[1])
    Cipher+=C3
    Cipher+=C4
    return Cipher

#Decryption function of one round
#input: Cipher text in 128-bit binary output: plaintext of corresponding ciphertext in binary
def decryption(ct,j, DecKey):
    l = []
    for i in range(0,len(ct),32):
        l.append(ct[i:i+32])
    Plaintext=''
    P1 = xnor(l[0],DecKey[4-j])
    Plaintext+=P1
    DFL1 = Ffunction(l[0][:16])+Ffunction(l[0][16:])
    P3 = xor2(DFL1,l[1])
    P4 = xnor(l[3],DecKey[4-j])
    DFR1 = Ffunction(l[3][:16])+Ffunction(l[3][16:])
    P2 = xor2(DFR1,l[2])
    Plaintext+=P2
    Plaintext+=P3
    Plaintext+=P4
    return Plaintext

#Main encryption function
#input: plaintext data to be encrypted in english output:Ciphertext for the given plaintext along with padding
def Encryption(plaintext, encryptionroundkeys):
    Encrypted = ''
    x = plaintext.encode('utf-8')
    hexplaintext = x.hex()
    binplaintext=''
    for i in hexplaintext:
        binplaintext+=hex_to_bin[i]
    paddedlist = padding(binplaintext)
    for i in paddedlist:
        for j in range(5):
            txt = encryption(i,j, encryptionroundkeys)
        Encrypted+=txt
    return Encrypted

#Main decryption function
#input: Ciphertext in the form of binary output:Plaintext of the corresponding ciphertext
def Decryption(ciphertext, deckey):
    listofenc = []
    for i in range(0,len(ciphertext),128):
        listofenc.append(ciphertext[i:i+128])
    Plaintext = ''
    for i in listofenc:
        for j in range(5):
            txt = decryption(i,j, deckey)
    Plaintext+=txt
    hexpt=''
    for i in range(0,len(Plaintext),4):
        hexpt+=bin_to_hex[Plaintext[i:i+4]]
    finalplain = bytes.fromhex(hexpt).decode('utf-8')
    return finalplain
# Create your views here.
def home(request):
    return render(request, 'home.html')

def userinput(request):
    option = request.GET['plaintext']
    return render(request, 'Sender1.html',{'option':option})

def getfilepath(file, ext):
    if ext == 'image':
        file_path = os.path.join('uploads', "image.jpg")
    else:
        file_path = os.path.join('uploads', 'file.txt')
    with open(file_path, 'wb+') as destination:
        for chunk in file.chunks():
            destination.write(chunk)
    if ext == 'image':
        shutil.copyfile(file_path, os.path.join('static\images\image.jpg'))
    else:
        shutil.copyfile(file_path, os.path.join('static\images\\file.txt'))
    return file_path

def iencryption(pt,j, EncryptionRoundKeys):
    P = []
    Cipher = ''
    for i in range(0,len(pt),32):
        P.append(pt[i:i+32])
    R011 = xnor(P[0],EncryptionRoundKeys[j])
    C1 = R011 #Cipher 1
    EFL1 = Ffunction(R011[:16])+Ffunction(R011[16:])
    Cipher+=R011
    R014 = xnor(P[3],EncryptionRoundKeys[j])
    C4 = R014 #Cipher 4
    EFR1 = Ffunction(R014[:16])+Ffunction(R014[16:])
    C2 = xor2(EFL1,P[2])
    Cipher+=C2
    C3 = xor2(EFR1,P[1])
    Cipher+=C3
    Cipher+=C4
    return Cipher

#Decryption function of one round
#input: Cipher text in 128-bit binary output: plaintext of corresponding ciphertext in binary
def idecryption(ct,j, DecKey):
    l = []
    for i in range(0,len(ct),32):
        l.append(ct[i:i+32])
    Plaintext=''
    P1 = xnor(l[0],DecKey[4-j])
    Plaintext+=P1
    DFL1 = Ffunction(l[0][:16])+Ffunction(l[0][16:])
    P3 = xor2(DFL1,l[1])
    P4 = xnor(l[3],DecKey[4-j])
    DFR1 = Ffunction(l[3][:16])+Ffunction(l[3][16:])
    P2 = xor2(DFR1,l[2])
    Plaintext+=P2
    Plaintext+=P3
    Plaintext+=P4
    return Plaintext

#Main encryption function
#input: plaintext data to be encrypted in english output:Ciphertext for the given plaintext along with padding
def iEncryption(plaintext, encryptionroundkeys):
    Encrypted = ''
    # x = plaintext.encode('utf-8')
    # hexplaintext = x.hex()
    # binplaintext=''
    # for i in hexplaintext:
    #     binplaintext+=hex_to_bin[i]
    paddedlist = padding(plaintext)
    for i in paddedlist:
        for j in range(5):
            txt = iencryption(i,j, encryptionroundkeys)
        Encrypted+=txt
    return Encrypted

#Main decryption function
#input: Ciphertext in the form of binary output:Plaintext of the corresponding ciphertext
def iDecryption(ciphertext, deckey):
    listofenc = []
    for i in range(0,len(ciphertext),128):
        listofenc.append(ciphertext[i:i+128])
    Plaintext = ''
    for i in listofenc:
        for j in range(5):
            txt = idecryption(i,j, deckey)
        Plaintext+=txt
    # hexpt=''
    # for i in range(0,len(Plaintext),4):
    #     hexpt+=bin_to_hex[Plaintext[i:i+4]]
    # finalplain = bytes.fromhex(hexpt).decode('utf-8')
    return Plaintext

def deleteallfiles():
    
    folder = 'C:\\Users\\madhv\\Desktop\\VSC\\Django\\Mini project\\Sender\\miniproject\\uploads'
    for filename in os.listdir(folder):
        file_path = os.path.join(folder, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print('Failed to delete %s. Reason: %s' % (file_path, e))

def forenc(request):
    try:
        imageselected = request.FILES['file']
        deleteallfiles()
        ext = imageselected.name.split(".")
        if(ext[1] == 'jpg' or ext[1] == 'png'):
            with open(getfilepath(imageselected, 'image'), 'rb') as image_file:
                image_data = image_file.read()
            binary_data = base64.b64encode(image_data)
            binary_string = ''.join(format(byte, '08b') for byte in binary_data)
            Originalplaintext = binary_string
            x1,x2,randkey = kcbingenerator()
            dk = decryptionkey(x2)
            EncryptionRoundKeys = keygenerator(x1)
            DecryptionRoundKeys = decryptionkeygenerator(dk)
            Deckey = []
            Deckey.append(DecryptionRoundKeys[0])
            Deckey.append(DecryptionRoundKeys[4])
            Deckey.append(DecryptionRoundKeys[1])
            Deckey.append(DecryptionRoundKeys[2])
            Deckey.append(DecryptionRoundKeys[3])
            etext = iEncryption(Originalplaintext, EncryptionRoundKeys)                   #Contains the ciphertext in the form of binary.
            #Converting the binary ciphertext in the form of hexadecimal
            hexpt=''
            for i in range(0,len(etext),4):
                hexpt+=bin_to_hex[etext[i:i+4]]
            bytedata = bytes.fromhex(hexpt)
            image_np = np.frombuffer(bytedata, dtype = np.uint8)
            enc_img = Image.fromarray(image_np)
            enc_img.save('C:\\Users\\madhv\\Desktop\\VSC\\Django\\Mini project\\Sender\\miniproject\\static\\images\\cipher.png')
            Finalcipher = bytes.fromhex(hexpt).decode('latin-1')
            f = Finalcipher.encode('latin-1')
            l = f.hex()
            f = open("Encrypted.txt", 'w', encoding='utf-8')
            f.write("image")
            f.write("\n")
            f.write(x2)
            f.write("\n")
            f.write(etext)
            f.write("\n")
            
            return render(request, 'after.html', { 'Cipher':Finalcipher, 'enckey':x1, 'rand':randkey})
        elif ext[1] == 'txt':
            with open(getfilepath(imageselected, 'text'), 'r') as file:
                Originalplaintext = file.read()
                x1,x2, key = kcbingenerator()
                dk = decryptionkey(x2)
                EncryptionRoundKeys = keygenerator(x1)
                DecryptionRoundKeys = decryptionkeygenerator(dk)
                Deckey = []
                Deckey.append(DecryptionRoundKeys[0])
                Deckey.append(DecryptionRoundKeys[4])
                Deckey.append(DecryptionRoundKeys[1])
                Deckey.append(DecryptionRoundKeys[2])
                Deckey.append(DecryptionRoundKeys[3])
                etext = Encryption(Originalplaintext, EncryptionRoundKeys)
                hexpt=''
                for i in range(0,len(etext),4):
                    hexpt+=bin_to_hex[etext[i:i+4]]
                Finalcipher = bytes.fromhex(hexpt).decode('latin-1')
                f = open("Encrypted.txt", 'w', encoding='utf-8')
                f.write("file")
                f.write("\n")
                f.write(x2)
                f.write("\n")
                f.write(etext)
                f.write("\n")
                return render(request, 'afterencrypt.html', { 'plaintext':Originalplaintext, 'Randomkey':key, 'x1':x1, 'x2':x2, 'Cipher':Finalcipher} )
    except:
        Originalplaintext = request.GET['plain']
        x1,x2, key = kcbingenerator()
        dk = decryptionkey(x2)
        EncryptionRoundKeys = keygenerator(x1)
        DecryptionRoundKeys = decryptionkeygenerator(dk)
        Deckey = []
        Deckey.append(DecryptionRoundKeys[0])
        Deckey.append(DecryptionRoundKeys[4])
        Deckey.append(DecryptionRoundKeys[1])
        Deckey.append(DecryptionRoundKeys[2])
        Deckey.append(DecryptionRoundKeys[3])
        etext = Encryption(Originalplaintext, EncryptionRoundKeys)
        hexpt=''
        for i in range(0,len(etext),4):
            hexpt+=bin_to_hex[etext[i:i+4]]
        Finalcipher = bytes.fromhex(hexpt).decode('latin-1')
        f = open("Encrypted.txt", 'w', encoding='utf-8')
        f.write("text")
        f.write("\n")
        f.write(x2)
        f.write("\n")
        f.write(etext)
        f.write("\n")
        return render(request, 'afterencrypt.html', { 'plaintext':Originalplaintext, 'Randomkey':key, 'x1':x1, 'x2':x2, 'Cipher':Finalcipher} )