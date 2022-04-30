import random

# Implementation of ElGamal Cryptographic System
class ElGamal:

  #Function to calculate (a^x)mod(m) efficiently using binary exponentiation
  def binary_exponentiation(self,a,x,m):
    res=1
    while x:
      if x&1: res=(res*a)%m
      a=(a*a)%m
      x>>=1
    return res

  #Function used for genarating key by receiving side
  def key_generation(self, q, alpha):
    # q is a prime number
    # alpha<q and is a primitive root of q 

    # Select 1<X_A<q-1
    X_A=random.randint(2,q-2)
    # Calculate Y_A = (alpha^X_A) mod(q)
    Y_A=self.binary_exponentiation(alpha,X_A,q)

    # private_key=X_A
    PR=X_A
    # public_key= [q,alpha,X_A]
    PU=(q,alpha,Y_A)

    #return private key and public key
    return PR,PU

  #Function to encrypt a message M<q using public key PU
  def encrypt(self,M,PU):

    # Unpack parameters q, alpha and Y_A from public key
    (q,alpha,Y_A) = PU
    # select 1<k<q
    k= random.randint(2,q-1)
    # Calculate K=(Y_A^k)mod(q)
    K= self.binary_exponentiation(Y_A,k,q)
    # Calculate C1=(alpha^k)mod(q)
    C1= self.binary_exponentiation(alpha,k,q)
    # Calculate C2=(KM)mod(q)
    C2= (K*M)%q

    #return cypher text as (C1,C2)
    C=(C1,C2)
    return C

  #Function to decrypt a cypher text C using public key PU and private key PR
  def decrypt(self,C,private_key,public_key):
    
    # Unpack C1 and C2 from cypher text C
    (C1,C2) = C
    # Unpack parameters q, alpha and Y_A from public key
    (q,alpha,Y_A) = public_key
    X_A = private_key

    # Calculate K^(-1) = (C1^(q-1-X))mod(q)
    K_inverse = self.binary_exponentiation(C1,q-1-X_A,q)
    # Decypher message M=(C2*(K^(-1)))mod(q)
    M= ( C2*K_inverse )%q

    return M

elGamal=ElGamal()

# Value of parameters
q,alpha=10711,859

# Key Generation
private_key,public_key=elGamal.key_generation(q,alpha)

# Message m<q
message=6766
print(f"Original message is {message}")

# Encryption using public key
Cypher_Text=elGamal.encrypt(message,public_key)
print(f"Encrypted cypher text is {Cypher_Text}")

# Decryption using public key and private key
decrypted=elGamal.decrypt(Cypher_Text,private_key,public_key)
print(f"Decrypted text is {decrypted}")
