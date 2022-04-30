from tests import *

# Implementation of Exclusive OR Generator class
class ExclusiveORGenerator:
  def __init__(self, bit_sequence):
    # bit sequence is 1,27-bit long seed 
    self.bs=bit_sequence
    # Number of bits in the bit sequence
    self.num=len(bit_sequence)

   # Function to generate one random bit
  def get_next_one_random_bit(self):
    # Calculate X[i] = X[i-1] XOR X[i-127]
    random_bit= (self.bs[self.num-1]^self.bs[self.num-127])
    # Append the next bit to list of bit sequence
    self.bs.append(random_bit)
    # Increment number of bits
    self.num+=1
    return random_bit
  
  # Function to generate num random bits
  def get_next_num_random_bits(self,num):
    random_bits=[]
    for i in range(num):
      # generate one random bit and append it to the list of random bits
      Bi=self.get_next_one_random_bit()
      random_bits.append(Bi)
    return random_bits

# seed bit sequence of 127 length
bit_sequence =  [0,0,0,1,0,1,1,0,1,1,0,1,1,0,0,1,0,0,0,1,\
                 0,1,1,1,1,0,0,1,0,0,1,0,1,0,0,1,1,0,1,1,\
                 1,0,1,1,0,1,0,0,0,1,0,0,0,0,0,0,1,0,1,0,\
                 1,1,1,1,1,1,1,0,1,0,1,0,0,1,0,0,0,0,1,0,\
                 1,0,1,1,0,1,1,0,0,0,0,0,0,0,0,0,0,1,0,0,\
                 1,1,0,0,0,0,1,0,1,1,1,0,0,1,1,1,1,1,1,1,1,1,0,0,1,1,1]

# Generate and print random bits
eog=ExclusiveORGenerator(bit_sequence)
random_bits=eog.get_next_num_random_bits(100)
print("Random bits:", random_bits, end="\n\n")

# Apply freuency test
frequency_test(random_bits)

# Apply runs test
runs_test(random_bits)