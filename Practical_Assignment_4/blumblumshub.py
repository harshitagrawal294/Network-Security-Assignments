from tests import *

# Implementation of BlumBlumShub random number generator class
class BlumBlumShub:

  # Class constructor to initialize the parameters of BlumBlumShub Generator
  def __init__(self,p,q,s):
    # p and q are two large prime number leaving remainder 3 when divided by 4
    # s is chosen to be relatively prime to p and q
    self.p=p    
    self.q=q
    # Calculate n = p x q
    self.n=p*q
    # Calculate X_0 = (s^2)mod(n)
    self.x=(s*s)%(self.n)
  
  # Function to generate one random bit
  def get_next_one_random_bit(self):
    # Calculate X[i] =  (X[i-1] ^ 2)mod(n)
    self.x=(self.x*self.x)%(self.n)
    # Calculate B[i] = X[i] mod 2
    random_bit= (self.x%2)
    return random_bit

  # Function to generate num random bits
  def get_next_num_random_bits(self,num):
    random_bits=[]
    for i in range(num):
      # generate one random bit and append it to the list of random bits
      Bi=self.get_next_one_random_bit()
      random_bits.append(Bi)
    return random_bits

# Value of parameters
p,q,s=10007,25247,40639

# Generate and print random bits
bbs=BlumBlumShub(p,q,s)
random_bits=bbs.get_next_num_random_bits(100)
print("Random bits:", random_bits, end="\n\n")

# Apply freuency test
frequency_test(random_bits)

# Apply runs test
runs_test(random_bits)