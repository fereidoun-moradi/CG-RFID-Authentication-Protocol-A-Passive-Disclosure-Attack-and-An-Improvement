#Python 3.6.1 [GCC 4.8.2] on linux
from random import *
NumExperiments=1
import numpy
'''
    A pseudo random number generator based on the hash specified in the hash_func.
    
    The PRNG is initialized with an integer seed, and produces 16-bit pseudo random numbers
       
    Internally, the PRNG uses a hash function to generate outputs. The hash 
       function produces 32-bit numbers, and both upper 16-bits and lower 
       16-bits are used as outputs. As an optimization, the seed is also used
       as the output of the hash, saving one application of the hash function.
'''
def PRNG(seed):
    next_values = [(seed >> 16) & 0xFFFF, seed & 0xFFFF]
    i = 3546839273
    # Hash the seed with the current index
    hash_output = hash_func(seed, i)
    next_values = next_values + [(hash_output >> 16) & 0xFFFF, hash_output & 0xFFFF]
    i = (i + 3546839273) & ((1 << 32) - 1)
    return next_values[3]
'''
    Hashes together two integers, seed_x and y.
    @return a 32-bit integer, result of the hash.
'''   
def hash_func(seed_x, y):
    
    # initialize with seed_x
    hash_state = lookup3Init(seed_x)
    
    # add y into hashed state
    lookup3Update(hash_state, y)
    
    # digest the hash and return the output value
    return lookup3Digest(hash_state)

# \brief Initializes lookup3 state
def lookup3Init(val):
    return numpy.array([0xdeadbeef + val] * 3, dtype=numpy.uint32);

# \brief Updates lookup3 state
def lookup3Update(state, data):
    def rot(x,k):
        return (((x) << (k)) | ((x) >> (32-(k))))
    state[1] += data
    state[2] ^= state[1]; state[2] -= rot(state[1],14); \
    state[0] ^= state[2]; state[0] -= rot(state[2],11); \
    state[1] ^= state[0]; state[1] -= rot(state[0],25); \
    state[2] ^= state[1]; state[2] -= rot(state[1],16); \
    state[0] ^= state[2]; state[0] -= rot(state[2],4);  \
    state[1] ^= state[0]; state[1] -= rot(state[0],14); \
    state[2] ^= state[1]; state[2] -= rot(state[1],24); \

# brief Returns digest from lookup3 state
def lookup3Digest(state):
    return state[2];

# CG+ authentication protocol
def CGpluse(L):
	SSK, ID, s, N2 = L[0], L[1], L[2], L[3]
	N1=PRNG(s)
	A=PRNG(ID^N1)^PRNG(SSK^N2)
	B=N2^ID
	C=s^SSK^PRNG(N2)
	IDSnew=PRNG(ID)
	SSKnew=PRNG(SSK)
	O=[A, B, C, N1]
	return O 

#The 16-bit dictionary is used in the proposed attack
N=[]
for m in range((2**16)-1):
  N.append(PRNG(m))

#The number of NumExperiments 
for r in range(NumExperiments):
    
    #The random produced 16-bit digits
    I=[]
    for n in range(4):
	    I.append(randint(0,(2**16)-1)& 0xFFFF)
    NI=I 

    #Running one session of the protocol
    Protocol_Output=CGpluse(I)
  
    #Obtain the value s for this session
    for i in range((2**16)-1):
      if Protocol_Output[3]==N[i]: secret_s=i 
    
    #Extract secrect value N2
    for t in range((2**16)-1):
      N_2=t 
      I_D=N_2^Protocol_Output[1]
      SS_K=secret_s^PRNG(N_2)^Protocol_Output[2]
      if Protocol_Output[0]==PRNG(I_D^Protocol_Output[3])^PRNG(SS_K^N_2): DN2=N_2 
    #Extract secrect values ID and SSK
    I_D=DN2^Protocol_Output[1]
    SS_K=secret_s^PRNG(DN2)^Protocol_Output[2]
    

    print("The values for running of the CG+ protocol",
    " \nSSK<-",I[0]," \nID<-",I[1],"  \nseed<-",I[2],"  \nN2<-",I[3])
    print(" \nThe produced values from the runinng","  \nA<-",Protocol_Output[0]," \nB<-",Protocol_Output[1]," \nC<-",Protocol_Output[2]," \nN1<-",Protocol_Output[3])
    print('The discovered value for s is', secret_s,  'that is same as the produced seed')
    print('The discovered value for N2 is', DN2,  'that is same as the value for running the protocol')
    print('The discovered values for ID and SSK are', I_D, ',',SS_K,  'that are same as the values for running the protocol')

#All secrect values of CG+ are discovered.
