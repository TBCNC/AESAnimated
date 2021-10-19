'''
Notice: This is not designed to be a secure solution AT ALL, and could maybe be more efficient.
The whole purpose of this script is to demonstrate the process of ECB (which mind you, isn't secure) AES encryption/decryption with a custom input (message and key).
'''
#https://www.youtube.com/watch?v=EucPkcOYekE


import binascii
import numpy as np
import time
import os

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

#Generates the key schedule based on the number of rounds and original key matrix
def keySchedule(key: bytearray, rounds=10) -> bytearray:
    #keyRounds = key + bytearray([0x00]*rounds*16)
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
        else:
            wordA = getWord(keyRounds, wordPosition - 4)
            wordB = getWord(keyRounds, wordPosition - 1)
            result = byteXOR(wordA, wordB)
            keyRounds = addWord(keyRounds, result)
        wordPosition+=1
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

def subBytesMat(mat):
    width = len(mat[0])
    height = len(mat)
    for y in range(0,height):
        for x in range(0,width):
            currentItem = mat[y,x]
            replacementItem = sBox[currentItem]
            mat[y][x] = replacementItem

def shiftRows(mat):
    height = len(mat)
    for y in range(0,height):
        currentRow = mat[y,:]
        newRow = np.roll(currentRow,-y)
        mat[y,:] = newRow

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

        clear()
        frame += "(W{0} << 1) XOR (((W{1} >> 7) & 1) * 1b)" .format(w,w)
        print(frame)
        time.sleep(0.5)

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

        clear()
        frame += "({0} << 1) ^ ((({1} >> 7) & 1) * 1b)" .format(binascii.hexlify(r).decode(),binascii.hexlify(r).decode())
        print(frame)
        time.sleep(0.5)

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
            frame += "D{0}".format(i)
            print(frame)
            time.sleep(0.05)
            clear()

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

            clear()
            frame += "G{0}[{1}] ^ W{0}[{2}] ^ W{0}[{3}] ^ G{0}[{4}] ^ W{0}[{5}]".format(i,offsets[i][0],offsets[i][1],offsets[i][2],offsets[i][3],offsets[i][4])
            print(frame)
            time.sleep(0.5)

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

            clear()
            frame += "{0} ^ {1} ^ {2} ^ {3} ^ {4}".format(b[offsets[i][0]],a[offsets[i][1]],a[offsets[i][2]],b[offsets[i][3]],a[offsets[i][4]])
            print(frame)
            time.sleep(0.5)

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

            clear()
            frame += '0x{:02x}\n'.format(resWord[i])
            print(frame)
            time.sleep(0.2)

        clear()
        frame += "New Word {0}: {1}".format(w,resWord)
        print(frame)
        time.sleep(2.0)
    
    clear()
    frame = ""
    frame += "New Matrix:\n{0}\n".format(matToStr(res))
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

#This performs the actual algorithm for a matrix, put in animations, command options, etc perhaps another time soon, it is fucking 1:30am.
def aesAlgorithm(input, key, rounds=10):
    keyRounds = keySchedule(key,rounds)
    start = addRoundKey(input, keyRounds, 0)
    currentBlock = start
    for x in range(1,rounds):
        subBytesMat(currentBlock)
        shiftRows(currentBlock)
        mixed = mixColumns(currentBlock)
        currentBlock = addRoundKey(mixed, keyRounds, x)
    subBytesMat(currentBlock)
    shiftRows(currentBlock)
    return addRoundKey(currentBlock, keyRounds, rounds)


def subBytesAnimation(mat):
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
    time.sleep(0.2)
    clear()
    frameStr += "      |  S-BOX\n"
    print(frameStr)
    time.sleep(0.2)
    clear()
    frameStr += "      |\n"
    print(frameStr)
    time.sleep(0.2)
    clear()
    frameStr += "      v\n"
    print(frameStr)
    time.sleep(0.2)
    subBytesMat(mat)
    newMatrixStr = matToStr(mat)
    clear()
    frameStr += newMatrixStr
    print(frameStr)
    time.sleep(2)

def shiftRowsAnimation(mat):
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
        time.sleep(1.3)
    

testInput = np.array(bytearray([0x32,0x88,0x31,0xe0,0x43,0x5a,0x31,0x37,0xf6,0x30,0x98,0x07,0xa8,0x8d,0xa2,0x34]), dtype=np.ubyte)
testKey = np.array(bytearray([0x2b,0x28,0xab,0x09,0x7e,0xae,0xf7,0xcf,0x15,0xd2,0x15,0x4f,0x16,0xa6,0x88,0x3c]), dtype=np.byte)
testInput.shape = (4,4)
testKey.shape = (4,4)


print("Plaintext Input:")
print(matToStr(testInput))
print("Cipher Key:")
print(matToStr(testKey))
time.sleep(2.0)

'''
print("Input Matrix:")
print(matToStr(testInput))
print("Key Matrix:")
print(matToStr(testKey))
output = aesAlgorithm(testInput,testKey)

print("Result:")
print(matToStr(output))
'''

keyRounds = keySchedule(testKey,10)
start = addRoundKey(testInput, keyRounds, 0)

clear()

subBytesAnimation(start)
shiftRowsAnimation(start)
resMix = mixColumns(start)
cipherText = addRoundKey(resMix,keyRounds,1)

clear()
print("Ciphertext Result:")
print(matToStr(cipherText))