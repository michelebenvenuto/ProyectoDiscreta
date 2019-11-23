#UNIVERSIDAD DEL VALLE DE GUATEMALA
#MM2025 - 2019
#Authors:
#Gustavo Mendez - 18500
#Michele Benvenuto - 18232
#Luis Urbina - 18473
#DESCRIPTION: Program to perform RSA cipher, usign Euclid's, Rabin-Miller, Karatsuba Fast Multiplication algorithms

import random
import sys
import math
import textwrap

from random import randrange

primesBelowFourDigits =   [3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97
                            ,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179
                            ,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269
                            ,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367
                            ,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461
                            ,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571
                            ,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661
                            ,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773
                            ,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883
                            ,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997]

#Function to get gcd of two digits, Euclid's algorithm
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


#Function to use Miller–Rabin primality test, an algorithm which determines whether a given number is prime
def rabinMillerTest(n, k=10):
    #k is the number of rounds of testing to perform, while n is an odd integer to be tested
    if n == 2:
        return True
    if not n & 1:
        return False

    #Inner function to check values
    def check(a, s, j, n):
        x = pow(a, j, n)
        if x == 1:
            return True
        for j in range(1, s - 1):
            if x == n - 1:
                return True
            x = pow(x, 2, n)
        return x == n - 1

    s = 0
    j = n - 1

    while j % 2 == 0:
        j >>= 1
        s += 1

    for j in range(1, k):
        a = randrange(2, n - 1)
        if not check(a, s, j, n):
            return False
    return True

#Function to check if a numer is prime, if its a large number, we'll check number with Rabin-Miller test
def isPrime(n):
    #primesBelowFourDigits is all primes under 1000. without resorting to Rabin-Miller     
    if (n >= 3):
        if (n & 1 != 0):
            for p in primesBelowFourDigits:
                if (n == p):
                    return True
                if (n % p == 0):
                    return False
            return rabinMillerTest(n)
    return False

#Function to generate a large prime, where k is the desired bit length
def generateLargePrime(k):
    r = 100*(math.log(k, 2)+1)  # max attempts
    attempts = r
    while r > 0:
        n = random.randrange(2**(k-1), 2**(k))
        r -= 1
        if isPrime(n) == True:
            return n

    failure = "There's a failure, you have done " + str(attempts) + "attempts."
    return failure

#Function to get the multiplicative inverse given two numbers, returns a tuple
def multInverse(a, b):
    # tuple has the next form: (num, x, y) such that num = gcd(a, b) = ax + by    
    # num = gcd(a,b) x = multiplicitive inverse of a mod b | y = multiplicitive inverse of b mod a
    x = 0
    ly = 0
    y = 1
    lx = 1
    original_a = a  # Remember original a/b to remove
    original_b = b  

    #Extended algorithm to get multiplicative inverse
    while b != 0:
        q = a // b
        (a, b) = (b, a % b)
        (x, lx) = ((lx - (q * x)), x)
        (y, ly) = ((ly - (q * y)), y)
    if lx < 0:
        lx += original_b  # If neg wrap modulo original b
    if ly < 0:
        ly += original_a  # If neg wrap modulo original a

    return lx

#Function to multiply two numbers, using Karatsuba fast multiplication algorithm, more in https://en.wikipedia.org/wiki/Karatsuba_algorithm
def multiply(x, y):
    _CUTOFF = 1536
    if x.bit_length() <= _CUTOFF or y.bit_length() <= _CUTOFF:  # Base case
        return x * y
    else:
        n = max(x.bit_length(), y.bit_length())
        half = (n + 32) // 64 * 32
        mask = (1 << half) - 1
        xlow = x & mask
        ylow = y & mask
        xhigh = x >> half
        yhigh = y >> half

        a = multiply(xhigh, yhigh)
        b = multiply(xlow + xhigh, ylow + yhigh)
        c = multiply(xlow, ylow)
        j = b - a - c
        return (((a << half) + j) << half) + c


#Function to generate keypair, using method: https://juncotic.com/rsa-como-funciona-este-algoritmo/
def generateKeypair(keySize=10):
    p = generateLargePrime(keySize)
    #print(p)
    q = generateLargePrime(keySize)
    #print(q)

    if p == q:
        raise ValueError('p and q cannot be equal')

    #n = pq
    n = multiply(p, q)
    #z is the totient of n
    z = multiply((p-1), (q-1))
    #Choose an integer k such that k and z(n) are coprime
    k = random.randrange(1, z)
    #Use Euclid's Algorithm to verify that k and z(n) are coprime
    g = gcd(k, z)

    #While gcd != 1, search two coprime numbers
    while g != 1:
        k = random.randrange(1, z)
        g = gcd(k, z)

    #Use Extended Euclid's Algorithm to generate the private key
    j = multInverse(k, z)
    #Public key is (k, n) and private key is (j, n)
    return ((k, n), (j, n))

#Function to encrypt a text given a private key and the plain text
def encrypt(privateKey, plainText):
    #Unpack the key from tuple into its components
    key, n = privateKey
    #Convert each letter of text to numbers based on the character using a^b mod m
    #ord() function retuns integer representing the Unicode index of char
    cipher = [(ord(char) ** key) % n for char in plainText]
    #Return array of bytes
    return cipher

#Function to decrypt a text given a private key and the cipher text
def decrypt(publicKey, ciphertext):
    #Unpack the key from tuple into its components
    key, n = publicKey
    #Convert to plaintext based on the ciphertext and key using a^b mod m
    #chr() converts Unicode to char
    plain = [chr(pow(char, key, n)) for char in ciphertext]
    #Return array of bytes as a string
    return ''.join(plain)



wantsToContinue1= True
print("******************************************************")
print("------ WELCOME TO OUR RSA Encripter/Decripter ------\n")
print("******************************************************")
    
print("Generating recommended public/private keypairs . . .")
public, private = generateKeypair()
print("PUBLIC KEY: ", public, " - PRIVATE KEY: ", private, "\n\n")

while(wantsToContinue1==True):
    
    print("Please choose one of the following options:\n 1) Encode a message\n 2) Decode a message\n 3) Exit")
    choosedOption= int(input("> "))

    if(choosedOption==1):
        message = input("Please type the MESSAGE you want to encrypt: ")
        keypair= input("Please type the PRIVATE KEY, comma separated (example: 23,19): ")
        result = [x.strip() for x in keypair.split(',')]

        privateKey = int(result[0]), int(result[1])        
        encryptedMessage = encrypt(privateKey, message)

        print("Encrypted message is: ")
        print(','.join(map(lambda x: str(x), encryptedMessage)))
    
    elif(choosedOption==2):
        encryptedMessage = input("Please type the MESSAGE you want to decrypt: ")
        keypair= input("Please type the PUBLIC KEY, comma separated (example: 17,13): ")
        result = [x.strip() for x in keypair.split(',')]

        publicKey = int(result[0]), int(result[1]) 

        #Converting crypted text to array of bytes
        encryptedMessage = [x.strip() for x in encryptedMessage.split(',')]
        bytesCrypted = [int(i) for i in encryptedMessage]

        print("Decrypted message is:")
        print(decrypt(publicKey, bytesCrypted))

    elif(choosedOption==3):
        print("Good bye bro ;)")
        wantsToContinue1= False