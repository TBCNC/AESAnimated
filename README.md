# Terminal AES - An animated example of the AES algorithm
This small python script demonstrates the AES encryption algorithm and Rijandel key schedule algorithm for inputs less than 16 characters, which represents one block in AES. This script is not designed to be a cryptographically secure or efficient implementation, but simply a step-by-step demonstration of how the algorithm works.

The inspiration for this project comes from the following YouTube video on the algorithm: https://www.youtube.com/watch?v=gP4PqVGudtg

## How to use
In order to run the AES animation, you can provide a plaintext input and key in the following format:
```
python3 animatedaes.py <plain_text> <key> [rounds: Optional. 1 by default]
```

## Introduction
The AES algorithm is a block cipher, which means that the encryption is done on a block of 16 plaintext bytes. This can be seen in the below example for the plaintext "Hello World":
```
Plaintext Block (Empty portions padded with 0):
|48 65 6c 6c|
|6f 20 57 6f|
|72 6c 64 00|
|00 00 00 00|
```
Typically, when there are leftover bytes for a block, we would use a system such as PKCS7 to pad the remaining bytes. In this case, since this is an educational demonstration, we will just leave these as 0.

The same is also done with the key, which can be seen below for the example "Password":
```
Key Block (Empty portions padded with 0):
|70 61 73 73|
|77 6f 72 64|
|00 00 00 00|
|00 00 00 00|
```
## Rijandel Key Schedule
This algorithm helps generate the different round keys which will be used in the algorithm. Each round of the AES algorithm uses a different round key, which is also a block. The words of the original key are used to produce subsequent words. Here, we are defining a word to be a column of the block. For instance, the first word for the above key would be 70770000.

The key schedule algorithm works in the following format:
* If a word position i is a multiple of 4, perform RotWord and SubBytes on i-1 then XOR with the word at position i-4. Then, XOR this result with the ith word from the RCon schedule.
* Otherwise, calculate the word position i as the XOR of wi-1 and wi-4.

We generate 4*R extra words for the key schedule, where R is the amount of rounds. Hence, the result for the key password would be the following.

```
Key Schedule Generation [1 rounds]:
W0:70770000
W1:616f0000
W2:73720000
W3:73640000
W4: (SubBytes(RotWord(0)) ^ W3) ^ RCON0 ===> (4363638f ^ 73640000) ^ 01000000 ===> 3314638f ^ 01000000 ===> 3214638f
W5: W1 ^ W4 ===> 616f0000 ^ 3214638f ===> 537b638f
W6: W2 ^ W5 ===> 73720000 ^ 537b638f ===> 2009638f
W7: W3 ^ W6 ===> 73640000 ^ 2009638f ===> 536d638f

Key schedule obtained:   
|70 61 73 73 32 53 20 53|
|77 6f 72 64 14 7b 09 6d|
|00 00 00 00 63 63 63 63|
|00 00 00 00 8f 8f 8f 8f|
```
## AES Block Algorithm
The AES block algorithm has the following steps: (Each operation will be explained further on)
* At the start, perform AddRoundKey on the original cipher key.
* For each inner round r of AES, perform SubBytes, ShiftRows, MixColumns and AddRoundKey for words r*4 to (r+1)*4 in the key schedule.
* For the final round, perform only SubBytes and ShiftRows and AddRoundKey with the final round key.

## AES Operations
### SubBytes
This replaces every byte within the block with another byte using (in this case) a substitution table called SBOX (https://en.wikipedia.org/wiki/Rijndael_S-box) in order to create confusion. For this algorithm, we have predefined the box, but in normal applications this is computed on the fly. An example of this can be seen below:
```
Substitute Bytes:
|38 04 1f 1f|    
|18 4f 25 0b|    
|72 6c 64 00|    
|00 00 00 00|    
      |
      |  S-BOX   
      |
      v
|07 f2 c0 c0|    
|ad 84 3f 2b|    
|40 50 43 63|    
|63 63 63 63|
```
### ShiftRows
For every row in the block i, we rotate that row in the left direction by i positions. So for row 0 there would be no change, row 1 we would shift once, etc. We can see the result of this using the above example.
```
Shift Rows (Row 3 shifted by 3):
|07 f2 c0 c0|
|84 3f 2b ad|
|43 63 40 50|
|63 63 63 63|
```

### MixColumns
In this operation, we are performing a modulo multiplication on each column within the ciphertext block by a matrix called the Rijandel Galois Field. For this operation, I have used the following implementation that I found on Wikipedia, which simplifies the implementation: https://en.wikipedia.org/wiki/Rijndael_MixColumns#Implementation_example

The result of this implementation for the second word can be seen below:
```
Word 1:f23f6363
G1 ===> (W1 << 1) ^ (((W1 >> 7) & 1) * 1b) ===> (f23f6363 << 1) ^ (((f23f6363 >> 7) & 1) * 1b) ===> [511, 126, 198, 198]
D0 ===> G0[0] ^ W0[3] ^ W0[2] ^ G0[1] ^ W0[1]===>511 ^ 99 ^ 99 ^ 126 ^ 63===>0x1be
D1 ===> G1[1] ^ W1[0] ^ W1[3] ^ G1[2] ^ W1[2]===>126 ^ 242 ^ 99 ^ 198 ^ 99===>0x4a
D2 ===> G2[2] ^ W2[1] ^ W2[0] ^ G2[3] ^ W2[3]===>198 ^ 63 ^ 242 ^ 198 ^ 99===>0xae
D3 ===> G3[3] ^ W3[2] ^ W3[1] ^ G3[0] ^ W3[0]===>198 ^ 99 ^ 63 ^ 511 ^ 242===>0x197
New W1 ===> [D0,D1,D2,D3] ===> be4aae97
```
Note that in these results, we use the 2 least significant nibbles and ignore all other nibbles.

### AddRoundKey
This is a very simple operation, which takes the round key for round r, and XORs this block with the ciphertext block. An example can be seen below:
```
AddRoundKey (Round 0):
|48 65 6c 6c|
|6f 20 57 6f|
|72 6c 64 00|
|00 00 00 00|

Round Key (Round 0):  
|70 61 73 73|
|77 6f 72 64|
|00 00 00 00|
|00 00 00 00|

Block ^ RoundKey      
      |
      |
      |
      v
|38 04 1f 1f|
|18 4f 25 0b|
|72 6c 64 00|
|00 00 00 00|
```