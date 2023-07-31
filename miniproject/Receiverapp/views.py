from django.shortcuts import render
import random
import base64
from PIL import Image
import numpy as np
from io import BytesIO
import os
import cv2
import shutil
import cProfile             #Time usage analysis
import psutil               #memory usage analysis
import pstats 
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

def fake_decryption(ciphertext, deckey):
    listofenc = []
    for i in range(0,len(ciphertext),128):
        listofenc.append(ciphertext[i:i+128])
    Plaintext = ''
    for i in listofenc:
        for j in range(5):
            txt = decryption(i,j, deckey)
        Plaintext+=txt
    return Plaintext
    


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
    folder = "C:\\Users\\madhv\\Desktop\\VSC\\Django\\Mini project\\receiver\\miniproject\\static\\images"
    for filename in os.listdir(folder):
        if filename != 'background.jpg':
            file_path = os.path.join(folder, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print('Failed to delete %s. Reason: %s' % (file_path, e))

def decrypt(request):
    #deleteallfiles()
    f = open("C:\\Users\\madhv\\Desktop\\VSC\\Django\\Mini project\\Sender\\miniproject\\Encrypted.txt", "r", encoding='utf-8')
    lines = f.readlines()
    print(lines)
    x2 = lines[1].strip()
    enc = lines[2].strip()
    dk = decryptionkey(x2)
    DecryptionRoundKeys = decryptionkeygenerator(dk)
    Deckey = []
    Deckey.append(DecryptionRoundKeys[0])
    Deckey.append(DecryptionRoundKeys[4])
    Deckey.append(DecryptionRoundKeys[1])
    Deckey.append(DecryptionRoundKeys[2])
    Deckey.append(DecryptionRoundKeys[3])
    if lines[0] == 'text\n' or lines[0] == "file\n":
        # f = enc.encode('latin-1')
        # l = f.hex()
        # etext = ''
        # for i in l:
        #     etext+=hex_to_bin[i]
        hexx2 = ''
        for i in range(0,len(x2),4):
            b=x2[i:i+4]
            hexx2+=bin_to_hex[b]
        etext = enc
        ptext = Decryption(etext, Deckey)
        return render(request, 'afterdecrypt.html', { 'type':"text",'hexx2': hexx2, 'etext':enc, 'ptext':ptext, 'x2':x2 } )
    else:
        hexx2 = ''
        for i in range(0,len(x2),4):
            b=x2[i:i+4]
            hexx2+=bin_to_hex[b]
        ptext = iDecryption(enc, Deckey)
        binary_data = bytes(int(ptext[i:i+8], 2) for i in range(0, len(ptext), 8))
        decoded_data = base64.b64decode(binary_data)
        image = Image.open(BytesIO(decoded_data))
        image.save("static\\images\\Decryptedimage.jpg")
        return render(request, 'afterdecrypt.html', { 'type':"image",'hexx2': hexx2,'etext':enc, 'ptext':ptext , 'x2':x2 } )
def bitflipattack(request):
    f = open("C:\\Users\\madhv\\Desktop\\VSC\\Django\\Mini project\\Sender\\miniproject\\Encrypted.txt", "r", encoding='utf-8')
    lines = f.readlines()
    print(lines)
    x2 = lines[1].strip()
    enc = "".join(lines[2:]).strip()
    etext = enc
    dk = decryptionkey(x2)
    DecryptionRoundKeys = decryptionkeygenerator(dk)
    Deckey = []
    Deckey.append(DecryptionRoundKeys[0])
    Deckey.append(DecryptionRoundKeys[4])
    Deckey.append(DecryptionRoundKeys[1])
    Deckey.append(DecryptionRoundKeys[2])
    Deckey.append(DecryptionRoundKeys[3])
    if lines[0] == 'text\n':
        # f = enc.encode('latin-1')
        # l = f.hex()
        # etext = ''
        # for i in l:
        #     etext+=hex_to_bin[i]
        pos = random.randint(0,127)
        fake_etext = etext
        for i in range(0,127):
            if i == pos and fake_etext[i] == '0':
                fake_etext = etext[:pos]+'1'+etext[pos+1:]
            elif i == pos and fake_etext[i] == '1':
                fake_etext = etext[:pos]+'0'+etext[pos+1:]
        ptext = fake_decryption(etext, Deckey)
        fake_ptext = fake_decryption(fake_etext, Deckey)
        print(len(ptext)," ", len(fake_ptext))
        changes = 0
        for i in range(127):
            if fake_ptext[i] != ptext[i]:
                changes+=1
        percent = (changes/128)*100
        return render(request, 'analyse.html', {'pos':pos,'octext':etext, 'fctext':fake_etext, 'optext':ptext, 'fptext':fake_ptext, 'changes':changes, 'percent':percent})
    elif lines[0] == 'file\n':
        # f = enc.encode('latin-1')
        # l = f.hex()
        # etext = ''
        # for i in l:
        #     etext+=hex_to_bin[i]
        pos = random.randint(0,127)
        fake_etext = etext
        for i in range(0,127):
            if i == pos and fake_etext[i] == '0':
                fake_etext = etext[:pos]+'1'+etext[pos+1:]
            elif i == pos and fake_etext[i] == '1':
                fake_etext = etext[:pos]+'0'+etext[pos+1:]
        ptext = fake_decryption(etext, Deckey)
        fake_ptext = fake_decryption(fake_etext, Deckey)
        print(len(ptext)," ", len(fake_ptext))
        changes = 0
        for i in range(0,len(ptext)):
            if fake_ptext[i] != ptext[i]:
                changes+=1
        percent = (changes/len(ptext))*100
        return render(request, 'analyse.html', {'pos':pos,'octext':etext, 'fctext':fake_etext, 'optext':ptext, 'fptext':fake_ptext, 'changes':changes, 'percent':percent})
    else:
        poslist = [32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95]
        pos = poslist[random.randint(0,len(poslist))]
        fake_etext = etext
        for i in range(0,127):
            if i == pos and fake_etext[i] == '0':
                fake_etext = etext[:pos]+'1'+etext[pos+1:]
            elif i == pos and fake_etext[i] == '1':
                fake_etext = etext[:pos]+'0'+etext[pos+1:]
        ptext = iDecryption(enc, Deckey)
        fake_ptext = iDecryption(fake_etext, Deckey)
        obinary_data = bytes(int(ptext[i:i+8], 2) for i in range(0, len(ptext), 8))
        odecoded_data = base64.b64decode(obinary_data)
        oimage = Image.open(BytesIO(odecoded_data))
        oimage.save("static\\images\\Decryptedimage.jpg")
        try: 
            fbinary_data = bytes(int(fake_ptext[i:i+8], 2) for i in range(0, len(fake_ptext), 8))
            fdecoded_data = base64.b64decode(fbinary_data)
            fimage = Image.open(BytesIO(fdecoded_data))
            fimage.save("static\\images\\Modifieddecryptedimage.jpg")
        except:
            pass
        changes = 0
        for i in range(0,len(ptext)):
            if fake_ptext[i] != ptext[i]:
                changes+=1
        percent = (changes/len(ptext))*100
        return render(request, 'imageanalyse.html', {'pos':pos,'optext':ptext, 'octext':etext, 'fptext':fake_ptext, 'fctext':fake_etext, 'changes':changes, 'percent':percent})
    
def attackhome(request):
    return render(request, 'attackhome.html')

def uploaddictionary(request):
    return render(request, 'uploaddictionary.html')

def dictionaryattack(request):
    dictionary = request.FILES['file']
    keys = dictionary.readlines()
    keys = [key.strip() for key in keys]
    keys = [key.decode() for key in keys]
    print(keys)
    x2s = []
    for i in range(len(keys)):
        y = keys[i]
        temp = ''
        for j in y:
            temp+=hex_to_bin[str(j)]
        x2s.append(str(temp))
    wrongkeys = []
    rightkey = ''     
    f = open("C:\\Users\\madhv\\Desktop\\VSC\\Django\\Mini project\\Sender\\miniproject\\Encrypted.txt", "r", encoding='utf-8')
    lines = f.readlines()
    enc = "".join(lines[2:]).strip()
    if lines[0] == 'image\n':
        for i in range(len(x2s)):
            try:
                x2 = x2s[i]
                dk = decryptionkey(x2)
                DecryptionRoundKeys = decryptionkeygenerator(dk)
                Deckey = []
                Deckey.append(DecryptionRoundKeys[0])
                Deckey.append(DecryptionRoundKeys[4])
                Deckey.append(DecryptionRoundKeys[1])
                Deckey.append(DecryptionRoundKeys[2])
                Deckey.append(DecryptionRoundKeys[3])
                ptext = iDecryption(enc, Deckey)
                binary_data = bytes(int(ptext[i:i+8], 2) for i in range(0, len(ptext), 8))
                decoded_data = base64.b64decode(binary_data)
                image = Image.open(BytesIO(decoded_data))
                image.save("static\\images\\Decryptedimage.jpg")
                rightkey=keys[i]
                status = 1
                return render(request, 'dictresults.html', {'type':'image', 'status':status, 'wrongkeys': wrongkeys, 'rightkey':rightkey})
            except:
                wrongkeys.append(keys[i])
                status = 0
        return render(request, 'dictresults.html', {'type': 'image', 'status':status, 'wrongkeys': wrongkeys, 'rightkey':rightkey})
    else:
        for i in range(len(x2s)):
            try:
                x2 = x2s[i]
                dk = decryptionkey(x2)
                DecryptionRoundKeys = decryptionkeygenerator(dk)
                Deckey = []
                Deckey.append(DecryptionRoundKeys[0])
                Deckey.append(DecryptionRoundKeys[4])
                Deckey.append(DecryptionRoundKeys[1])
                Deckey.append(DecryptionRoundKeys[2])
                Deckey.append(DecryptionRoundKeys[3])
                etext = enc
                ptext = Decryption(etext, Deckey)
                rightkey=keys[i]
                status = 1
                return render(request, 'dictresults.html', {'type': 'text', 'status':status, 'wrongkeys': wrongkeys, 'rightkey':rightkey, 'plain':ptext})
            except:
                wrongkeys.append(keys[i])
                status = 0
        return render(request, 'dictresults.html', {'type': 'text', 'status':status, 'wrongkeys': wrongkeys, 'rightkey':rightkey})



def npcr(original_image, encrypted_image):
    original_array = np.array(original_image)
    encrypted_array = np.array(encrypted_image)
    npcr = np.mean(original_array != encrypted_array) * 100
    return npcr
    
def uaci(original_image, encrypted_image):
    original_array = np.array(original_image)
    encrypted_array = np.array(encrypted_image)
    uaci = np.mean(np.abs(original_array - encrypted_array))
    return uaci

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

def statsenc(plaintext, encryptionroundkeys):
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

def analysis(request):
    f = open("C:\\Users\\madhv\\Desktop\\VSC\\Django\\Mini project\\Sender\\miniproject\\Encrypted.txt", "r", encoding='utf-8')
    lines = f.readlines()
    if lines[0] == 'image\n':
        # img1 = cv2.imread('C:\\Users\\madhv\\Desktop\\VSC\\Django\\Mini project\\receiver\\miniproject\\static\\images\\Decryptedimage.jpg', cv2.IMREAD_GRAYSCALE)
        # img2 = cv2.imread('C:\\Users\\madhv\\Desktop\\VSC\\Django\\Mini project\\receiver\\miniproject\\static\\images\\Modifieddecryptedimage.jpg', cv2.IMREAD_GRAYSCALE)
        # img1_arr = np.array(img1)
        # img2_arr = np.array(img2)
        # npcr = np.sum(img1_arr != img2_arr) / img1_arr.size
        # uaci = np.sum(np.abs(img1_arr - img2_arr)) / (img1_arr.size * 255)
        x1,x2, randkey = kcbingenerator()
        EncryptionRoundKeys = keygenerator(x1)
        with open("C:\\Users\\madhv\\Desktop\\VSC\\Django\\Mini project\\receiver\\miniproject\\static\\images\\Decryptedimage.jpg", 'rb') as image_file:
            image_data = image_file.read()
        binary_data = base64.b64encode(image_data)
        binary_string = ''.join(format(byte, '08b') for byte in binary_data)
        profiler = cProfile.Profile()
        result = profiler.runcall(statsenc, binary_string, EncryptionRoundKeys)
        stats = profiler.getstats()
        # profiler.disable()
        enc_stats_str ="\n".join([str(s) for s in stats]) 
        # enc_stats_str = stats_str.strip_dirs().sort_stats('cumulative').print_stats()
        # dk = decryptionkey(x2)
        # DecryptionRoundKeys = decryptionkeygenerator(dk)
        # Deckey = []
        # Deckey.append(DecryptionRoundKeys[0])
        # Deckey.append(DecryptionRoundKeys[4])
        # Deckey.append(DecryptionRoundKeys[1])
        # Deckey.append(DecryptionRoundKeys[2])
        # Deckey.append(DecryptionRoundKeys[3])
        # profiler2 = cProfile.Profile()
        # profiler2.enable()
        # stats1 = iDecryption(stats, Deckey)
        # profiler2.disable()
        # dec_stats_str = profiler2.print_stats()
        # dec_stats_str = stats_str1.strip_dirs().sort_stats('cumulative').print_stats()
        return render(request, 'analysis.html', {'encstats':enc_stats_str, 'result':result})