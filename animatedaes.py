'''
(C) 2021 Charles Hampton-Evans

Notice: This is not designed to be a secure solution AT ALL, and it is definitely not designed to be efficient.
The whole purpose of this script is to demonstrate the steps of AES encryption/decryption with a small custom plaintext input, small custom key and small round count (message and key).
In reality, you would most likely use 10+ rounds and a longer plaintext input which uses CBC and an IV, and a key which is generated using a key generation algorithm (PBKDF2).
TL;DR This code is an educational proof of concept.
'''

import binascii
import numpy as np
import time
import os
import sys

#Substitution box pulled from wikipedia
sBox = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]

#Round counstants for round key generation
rCon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

#Takes type bytearray
def rotWord(word : bytearray) -> bytearray:
    return bytearray(word[1:len(word)])+bytearray([word[0]])

#Uses the sbox to substitute bytes
def subBytes(word : bytearray) -> bytearray:
    return bytearray([sBox[int.from_bytes([x], byteorder='big')] for x in word])

def byteXOR(b1 : bytearray, b2: bytearray) -> bytearray:
    res = bytearray([])
    for x,y in zip(b1,b2):
        res.append(x ^ y)
    return res

def getWord(mat, pos):
    return bytearray(mat[:,pos])

#Adds a column which is of length word
def addWord(mat, word):
    #Assuming we are accepting input as bytearray
    wordAdjusted = np.array(word,dtype=np.byte)
    wordAdjusted.shape = (4,1)
    return np.append(mat,wordAdjusted,axis=1)

def drawArrow(frame):
    clear()
    frame += " ="
    print(frame)
    time.sleep(0.05)
    clear()
    frame += "="
    print(frame)
    time.sleep(0.05)
    clear()
    frame += "="
    print(frame)
    time.sleep(0.05)
    clear()
    frame += "> "
    print(frame)
    time.sleep(0.05)
    return frame

#Generates the key schedule based on the number of rounds and original key matrix
def keySchedule(key, rounds=10):
    clear()
    frame = "Key Schedule Generation [{0} rounds]:\n".format(rounds)
    for i in range(4):
        frame += "W{0}:{1}".format(i,binascii.hexlify(getWord(key,i)).decode()) + "\n"
    print(frame)
    time.sleep(1.0)
    keyRounds = key
    wordPosition = 4
    while wordPosition < 4+rounds*4:
        if wordPosition%4==0:
            startingWord = getWord(keyRounds, wordPosition - 1)
            substitutedWord = subBytes(rotWord(startingWord))
            previousWord = getWord(keyRounds , wordPosition - 4)
            xorPartA = byteXOR(previousWord,substitutedWord)
            rConWord = bytearray([rCon[int(wordPosition/4) - 1],0x0,0x0,0x0])
            resultingWord = byteXOR(xorPartA, rConWord)
            keyRounds = addWord(keyRounds, resultingWord)
            clear()
            frame += "W{0}: ".format(wordPosition)
            print(frame)
            time.sleep(0.05)
            clear()
            
            frame += "(SubBytes(RotWord({0})) ^ W{1}) ^ RCON{2}".format(str(wordPosition-4),str(wordPosition - 1),str(int(wordPosition/4)-1))
            print(frame)
            time.sleep(0.1)
            frame = drawArrow(frame)
            
            clear()
            frame += "({0} ^ {1}) ^ {2}".format(binascii.hexlify(substitutedWord).decode(), binascii.hexlify(startingWord).decode(), binascii.hexlify(rConWord).decode())
            print(frame)
            time.sleep(0.1)

            frame = drawArrow(frame)

            clear()
            frame += "{0} ^ {1}".format(binascii.hexlify(xorPartA).decode(), binascii.hexlify(rConWord).decode())
            print(frame)
            time.sleep(0.05)

            frame = drawArrow(frame)

            clear()
            frame += binascii.hexlify(resultingWord).decode() + "\n"
            print(frame)
            time.sleep(0.5)
        else:
            wordA = getWord(keyRounds, wordPosition - 4)
            wordB = getWord(keyRounds, wordPosition - 1)
            result = byteXOR(wordA, wordB)
            keyRounds = addWord(keyRounds, result)
            
            clear()
            frame += "W{0}: ".format(wordPosition)
            print(frame)
            time.sleep(0.05)

            clear()
            frame += "W{0} ^ W{1}".format(wordPosition-4,wordPosition-1)
            print(frame)
            time.sleep(0.05)

            frame = drawArrow(frame)

            clear()
            frame += "{0} ^ {1}".format(binascii.hexlify(wordA).decode(), binascii.hexlify(wordB).decode())
            print(frame)
            time.sleep(0.05)

            frame = drawArrow(frame)

            clear()
            frame += binascii.hexlify(result).decode() + "\n"
            print(frame)
            time.sleep(0.5)

        wordPosition+=1
    time.sleep(2.0)
    return keyRounds

#Custom print format
def matToStr(mat):
    strToPrnt = ""
    for y in range(0,len(mat)):
        strToPrnt += "|"
        for x in range(0,len(mat[y])):
            strToPrnt += str(binascii.hexlify(mat[y][x]).decode()) + " "
        strToPrnt = strToPrnt[:len(strToPrnt)-1]
        strToPrnt += "|"
        strToPrnt += "\n"
    return strToPrnt

def getRoundKey(keys, roundNumber):
    return keys[:, roundNumber*4:((roundNumber+1)*4)]

def mixColumns(mat):
    clear()
    frame = "Mix Columns:\n"
    frame += matToStr(mat)
    frame += "\n\n"
    print(frame)
    time.sleep(2)
    clear()
    res = np.zeros(mat.shape, dtype=np.ubyte)
    width = len(mat[0])
    #https://en.wikipedia.org/wiki/Rijndael_MixColumns
    for w in range(width):
        clear()
        frame = "MixColumns on Word " + str(w) + "\n"
        r = getWord(mat, w)
        frame += "Word " + str(w) + ":" + binascii.hexlify(r).decode() + "\n"
        print(frame)
        time.sleep(1)

        a = [0,0,0,0]
        b = [0,0,0,0]
        
        for c in range(4):
            a[c] = r[c]
            h = (r[c] >> 7) & 1
            b[c] = r[c] << 1
            b[c] ^= h * 0x1B
        
        clear()
        frame += "G" + str(w)
        print(frame)
        time.sleep(0.50)

        frame = drawArrow(frame)

        clear()
        frame += "(W{0} << 1) ^ (((W{1} >> 7) & 1) * 1b)" .format(w,w)
        print(frame)
        time.sleep(0.5)

        frame = drawArrow(frame)

        clear()
        frame += "({0} << 1) ^ ((({1} >> 7) & 1) * 1b)" .format(binascii.hexlify(r).decode(),binascii.hexlify(r).decode())
        print(frame)
        time.sleep(0.5)

        frame = drawArrow(frame)

        clear()
        frame += str(b) + "\n"
        print(frame)
        time.sleep(0.2)

        d0 = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]
        d1 = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]
        d2 = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]
        d3 = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]

        offsets = [[0,3,2,1,1],[1,0,3,2,2],[2,1,0,3,3],[3,2,1,0,0]]
        
        resWord = [d0,d1,d2,d3]
        res[:,w] = resWord

        for i in range(4):
            clear()
            frame += "D{0} ===> ".format(i)

            frame += "G{0}[{1}] ^ W{0}[{2}] ^ W{0}[{3}] ^ G{0}[{4}] ^ W{0}[{5}]".format(i,offsets[i][0],offsets[i][1],offsets[i][2],offsets[i][3],offsets[i][4])

            frame += "===>"
            
            frame += "{0} ^ {1} ^ {2} ^ {3} ^ {4}".format(b[offsets[i][0]],a[offsets[i][1]],a[offsets[i][2]],b[offsets[i][3]],a[offsets[i][4]])

            frame += "===>"

            frame += '0x{:02x}\n'.format(resWord[i])
            print(frame)
            time.sleep(0.2)

        clear()
        frame += "New W{0}".format(w)
        frame += " ===> [D0,D1,D2,D3] ===> "
        frame += '{0}\n'.format(binascii.hexlify(getWord(res,w)).decode())
        print(frame)
        time.sleep(2.0)
    
    clear()
    frame = ""
    frame += "Cipherblock after MixColumns:\n{0}\n".format(matToStr(res))
    print(frame)
    time.sleep(2.0)

    return res

def addRoundKey(mat, keys, roundNumber):
    clear()
    frame = "AddRoundKey (Round {0}):\n".format(roundNumber)
    frame += matToStr(mat) + "\n"
    print(frame)
    time.sleep(1.0)

    clear()
    frame += "Round Key (Round {0}):\n".format(roundNumber)
    frame += matToStr(getRoundKey(keys,roundNumber)) + "\n"
    print(frame)
    time.sleep(0.25)

    clear()
    frame += "Block "
    print(frame)
    time.sleep(0.2)

    clear()
    frame += "^"
    print(frame)
    time.sleep(0.2)

    clear()
    frame += " RoundKey\n"
    print(frame)
    time.sleep(0.2)

    clear()
    frame += "      |\n"
    print(frame)
    time.sleep(0.2)
    clear()
    frame += "      |\n"
    print(frame)
    time.sleep(0.2)
    clear()
    frame += "      |\n"
    print(frame)
    time.sleep(0.2)
    clear()
    frame += "      v\n"
    print(frame)
    time.sleep(0.2)

    result = np.array(np.bitwise_xor(mat, getRoundKey(keys, roundNumber)), dtype=np.ubyte)

    clear()
    frame += matToStr(result)
    print(frame)
    time.sleep(2.0)

    return result

def subBytesMat(mat):
    clear()
    frameStr = "Substitute Bytes:"
    print(frameStr)
    time.sleep(0.5)
    clear()
    matStrBefore = matToStr(mat)
    frameStr += "\n" + matStrBefore
    print(frameStr)
    time.sleep(0.5)
    clear()
    frameStr += "      |\n"
    print(frameStr)
    time.sleep(0.1)
    clear()
    frameStr += "      |  S-BOX\n"
    print(frameStr)
    time.sleep(0.1)
    clear()
    frameStr += "      |\n"
    print(frameStr)
    time.sleep(0.1)
    clear()
    frameStr += "      v\n"
    print(frameStr)
    time.sleep(0.1)
    width = len(mat[0])
    height = len(mat)
    for y in range(0,height):
        for x in range(0,width):
            currentItem = mat[y,x]
            replacementItem = sBox[currentItem]
            mat[y][x] = replacementItem
    newMatrixStr = matToStr(mat)
    clear()
    frameStr += newMatrixStr
    print(frameStr)
    time.sleep(2)

def shiftRows(mat):
    clear()
    frameStr = "Shift Rows:\n"
    print(frameStr)
    time.sleep(0.7)
    clear()
    originalMatrix = matToStr(mat)
    frameStr += originalMatrix
    print(frameStr)
    time.sleep(0.7)

    height = len(mat)
    for y in range(0,height):    
        clear()
        frameStr = "Shift Rows (Row " + str(y) + " shifted by " + str(y) + "):\n"
        currentRow = mat[y,:]
        newRow = np.roll(currentRow,-y)
        mat[y,:] = newRow
        matChange = matToStr(mat)
        frameStr += matChange
        print(frameStr)
        time.sleep(0.5)
    
#This performs the actual algorithm for a matrix, put in animations, command options, etc perhaps another time soon, it is fucking 1:30am.
def aesAlgorithm(input, key, rounds=10):
    clear()
    frame = "Starting AES algorithm for {0} rounds on the following plaintext input and key:".format(rounds)
    frame += "\nPlaintext Block:\n"
    frame += matToStr(input)
    frame += "\nKey Block:\n"
    frame += matToStr(key)
    print(frame)
    time.sleep(3.0)
    keyRounds = keySchedule(key,rounds)
    clear()
    frame = "Key schedule obtained:\n"
    frame += matToStr(keyRounds)
    print(frame)
    time.sleep(3.0)
    start = addRoundKey(input, keyRounds, 0)
    currentBlock = start
    for x in range(0,rounds):
        subBytesMat(currentBlock)
        shiftRows(currentBlock)
        mixed = mixColumns(currentBlock)
        currentBlock = addRoundKey(mixed, keyRounds, x+1)
        
        clear()
        frame = "Cipher block obtained after round {0}:\n".format(x+1)
        frame += matToStr(currentBlock)
        print(frame)
        time.sleep(1.0)
    
    clear()
    frame = "Cipher block before final round:\n"
    frame += matToStr(currentBlock)
    print(frame)
    time.sleep(2.0)
    subBytesMat(currentBlock)
    shiftRows(currentBlock)
    return addRoundKey(currentBlock, keyRounds, rounds)

testInput = np.array(bytearray([0x32,0x88,0x31,0xe0,0x43,0x5a,0x31,0x37,0xf6,0x30,0x98,0x07,0xa8,0x8d,0xa2,0x34]), dtype=np.ubyte)
testKey = np.array(bytearray([0x2b,0x28,0xab,0x09,0x7e,0xae,0xf7,0xcf,0x15,0xd2,0x15,0x4f,0x16,0xa6,0x88,0x3c]), dtype=np.byte)
testInput.shape = (4,4)
testKey.shape = (4,4)

arguments = sys.argv

helpText='''
    Terminal AES animation by Charles Hampton-Evans

    Usage:
    python3 animatedaes.py --help      -       Help screen
    python3 animatedaes.py "[plaintext input : Max 16 characters]" "[key : Max 16 characters]" [rounds : Optional, default is 1]

    Description:
    This program provides a step-by-step animation in the terminal of the AES algorithm using the Rijndael functions. This is not designed to be a secure solution, and for the moment, will take only inputs less than 16 characters. This is because AES is a block cipher, and the animation for one block already takes approximately one minute, so animating multiple blocks would be highly time consuming and would not change the educational outcome.
'''

if len(arguments) < 2:
    print("Not enough arguments provided. For advice, use -h or --help.")
    exit(1)

if arguments[1].lower() == "--help" or arguments[1].lower() == "-h":
    print(helpText)
    exit(1)

input = arguments[1]
key = arguments[2]

if len(input) > 16:
    print("Plaintext input too long, the maximum is 16 characters.")
    exit()

if len(key) > 16:
    print("Key too long, the maximum is 16 characters.")
    exit()

rounds = 1
if len(arguments) > 3:
    rounds = arguments[3]

inputBytes = bytearray()
inputBytes.extend(map(ord,input))
keyBytes = bytearray()
keyBytes.extend(map(ord,key))

print("Plaintext:" + input + " ===> " + binascii.hexlify(inputBytes).decode())
print("Key:" + key + " ===> " + binascii.hexlify(keyBytes).decode())

plainTextBlock = np.pad(np.array(inputBytes, dtype=np.byte),(0,16-len(input)))
plainTextBlock.shape = (4,4)

keyBlock = np.pad(np.array(keyBytes, dtype=np.byte),(0,16-len(key)))
keyBlock.shape = (4,4)

print("Plaintext Block (Empty portions padded with 0):")
print(matToStr(plainTextBlock))
print("Key Block (Empty portions padded with 0):")
print(matToStr(keyBlock))
time.sleep(2.0)

cipherText = aesAlgorithm(plainTextBlock, keyBlock, rounds)
clear()
print("Ciphertext block after {0} rounds:".format(rounds))
print(matToStr(cipherText))
cipherText.shape = (1,16)
print("Ciphertext result as a hexadecimal string:{0}".format(binascii.hexlify(cipherText).decode()))