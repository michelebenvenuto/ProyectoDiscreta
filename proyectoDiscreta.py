#Program for RSA Encription 
#Authors:
#Michele Benvenuto 18232
#Luis Urbina 
#Gustavo Mendez
 
import random

#function used to generate de public keys
# param 1 = array of prime numbers 
def publicKeyGenerator(primeArray):
    #Array used to return the 3 public keys
    publicKeys= []
    #Take two random prime numbers
    p=primeArray[random.randint(0, len(primeArray)-1)]
    q=primeArray[random.randint(0, len(primeArray)-1)]
    #Check if p and q are the same if they are change q
    while(p==q):
        q=primeArray[random.randint(0, len(primeArray)-1)]
    #Multiply both numbers
    n=p*q
    #z will be used to generate the private key 
    z=(p-1)*(q-1)
    #generate k
    k=primeArray[random.randint(0, len(primeArray)-1)]
    while(z%k==0):
        k=primeArray[random.randint(0, len(primeArray)-1)]
    publicKeys.append(n)
    publicKeys.append(k)
    publicKeys.append(z)
    return publicKeys

#function used to generate the private key from the public keys 
#param1 = array with the 3 public keys 
def privateKeyGenerator (publicKeys):
    privateKey=random.randint(0,publicKeys[2]-1)
    #we need k and z to generate the private key, these are stored in publicKeys[1] and 2 respectively 
    while(publicKeys[1]*privateKey%publicKeys[2]!=1):
        privateKey=random.randint(0,publicKeys[2]-1)
    return privateKey

#function used to encript
#param 1 = array with the generated public keys
#param 2 = message to encript
def Encription (publicKeys, message):
    a= message**publicKeys[1]
    return a%publicKeys[0]

#function used to decript
#param 1 = generated private key
#param 2 = generated public keys
#param 3 = message to decript
def decription (privateKey, publicKeys, message):
    a = message**privateKey
    return a%publicKeys[0]

#function used to change a string or number to an array of numbers or strings
#param 1 = string to change
#param 2 = assignation dictionary
def changer(message, assignDict):
    returnValue=[]
    for char in message:
        returnValue.append(assignDict[char])
    return returnValue

primeArray = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199]
letterToNumber= {'a':1,'b':2,'c':3,'d':4,'e':5,'f':6,'g':7,'h':8,
    'i':9,'j':10,'k':11,'l':12,'m':13,'n':14,'o':15,'p':16,'q':17,
    'r':18,'s':19,'t':20,'u':21,'v':22,'w':23,'x':24,'y':25,'z':26}
numbersToLetters= { 1 :'a', 2:'b', 3:'c', 4:'d', 5:'e', 6:'f', 7:'g', 8:'h',
     9:'i', 10:'j', 11:'k', 12:'l', 13:'m', 14:'n', 15:'o', 16:'p', 17:'q', 
    18:'r', 19:'s',20:'t',21:'u',22:'v',23:'w',24:'x',25:'y',26:'z'}
publicKeys=publicKeyGenerator(primeArray)
#publicKeys = [33,7,20]
privateKey=privateKeyGenerator(publicKeys)
encondedString= []
decodedString= []
stringToEncode= "estoesunapruebaparaverquetodofuncione"
stringToDecode= " "
finalproduct=""
choosedOption = 0
modifiedString= changer(stringToEncode,letterToNumber)
for i in modifiedString:
    numToAppend=Encription(publicKeys,i)
    encondedString.append(numToAppend)
print(encondedString)
for i in encondedString:
    letterToAppend=decription(privateKey,publicKeys,i)
    decodedString.append(letterToAppend)
finalDecode= changer(decodedString, numbersToLetters)
print(finalDecode)
#wantsToContinue1= True
#while(wantsToContinue1==True):
#    print("Welcome to our RSA encripter/decripter please choose one of the following options:\n 1) Encode a message\n 2) Decode a message\n 3) Exit")
#    choosedOption= int(input())
#    if(choosedOption==1):
#        print("Please type the message you want to encript: ")
#        stringToEncode= input()
#        modifiedString= changer(stringToEncode,letterToNumber)
#        for i in modifiedString:
#            numToAppend=Encription(publicKeys,i)
#            print(numToAppend)
#            inMod26=numToAppend%26
#            print(inMod26)
#            backToString=numbersToLetters[inMod26]
#            encondedString.append(backToString)
#        print(encondedString)
#    elif(choosedOption==2):
#        print("Please type the message you want to decript:")
#    elif(choosedOption==3):
#        print("Cy@")
#        wantsToContinue1= False


