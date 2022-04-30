import math

def frequency_test(numbers):
  s=0
  for x in numbers:
    if x==1: s+=1 #add 1 to s for every 1 bit in list of numbers
    else: s-=1  #subtract 1 to s for every 0 bit in list of numbers

  n= len(numbers) # number of pseudo random numbers generated
  root_n = math.sqrt(n)
  s_observed= abs(s)/root_n # calculate absolute value of observed sum divided by square root of n

  p_value= math.erfc(s_observed/math.sqrt(2)) # calculate P-value using error function

  if p_value<0.01: 
    print(f"p-value : {p_value} < 0.01. So, the sequence doesn't appear not random in frequency test") # if P-value if less than 0.01 then sequence is not random
  else:
    print(f"p-value : {p_value} >= 0.01. So, the sequence appears random in frequency test") # if P-value if more than 0.01 then sequence is random

def runs_test(numbers):
  num = len(numbers)  # number of pseudo random numbers

  # Calculate the number of runs in the list
  runs=0 
  for i in range(num-1):
    if numbers[i]!=numbers[i+1]: runs+=1

  # Calculate the fraction of 1's in the bit list
  pi=0
  for x in numbers: 
    if x==1: pi+=1
  pi/=num

  numerator= abs(runs-2*num*pi*(1-pi))  # |runs-2Nπ(1-π)|
  denominator= 2*math.sqrt(2*num)*pi*(1-pi) # (2*sqrt(2N)*π(1-π))

  p_value= math.erfc(numerator/denominator) # p_value = erfc(|V_N(obs)-2Nπ(1-π)|/(2*sqrt(2N)*π(1-π)))

  if p_value<0.01: 
    print(f"p-value : {p_value} < 0.01. So, the sequence doesn't appear not random in runs test") # if P-value if less than 0.01 then sequence is not random
  else:
    print(f"p-value : {p_value} >= 0.01. So, the sequence appears random in runs test") # if P-value if more than 0.01 then sequence is random
