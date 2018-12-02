from random import *
NumExperiments=1
import numpy

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

# Revised_CG+ authentication protocol
def Revised_CGpluse(L):
	SSK, ID, s1, s2, N2, EPC = L[0], L[1], L[2], L[3], L[4], L[5]
	N1=PRNG(s1)^PRNG(s2)
	A=PRNG(ID^N1)^PRNG(SSK^N2)
	B=N2^ID^EPC
	E=s1^SSK^PRNG(N2)
	F=s2^ID^PRNG(N2)
	IDSnew=PRNG(ID)
	SSKnew=PRNG(SSK)
	O=[A, B, E, F, N1]
	return O 


#The 16-bit dictionary is used in the proposed attack
N=[]
for m in range((2**16)-1):
  N.append(PRNG(m))

#The number of NumExperiments   
for r in range(NumExperiments):
    
    #The random produced 16-bit digits
    I=[]
    for n in range(6):
	    I.append(randint(0,(2**16)-1)& 0xFFFF)
    NI=I 

    #Running one session of the protocol
    Protocol_Output_firstsession=Revised_CGpluse(I)
    
    #The fresh random produced 16-bit digits for next session
    II=[]
    for z in range(4):
	    II.append(randint(0,(2**16)-1)& 0xFFFF)
    NII=II
    
    #Running next session of the protocol with same N1 of previous session
    W=II[0],II[1],NI[2],NI[3],II[2],II[3]
    Protocol_Output_secondsession=Revised_CGpluse(W)
   
    #Extract the secrect values s1 and N2
    A_delta=Protocol_Output_firstsession[0]^Protocol_Output_secondsession[0]
    N2_delta=Protocol_Output_firstsession[1]^Protocol_Output_secondsession[1]
    SSk_N2=0
    for i in range((2**16)-1):
      if A_delta==PRNG(i)^PRNG(i^N2_delta):SSk_N2=i 
      
    s_1=0
    for j in range((2**16)-1):
      s_1=j
      for k in range((2**16)-1):
       if SSk_N2^NI[2]==j^k^PRNG(k): N_2=k
    
    #Obtain the secrect value SSK
    SS_K=Protocol_Output_firstsession[2]^s_1^PRNG(N_2)
    
    #Obtain the secrect value s2
    for h in range((2**16)-1):
      if Protocol_Output_firstsession[4]==PRNG(s_1)^PRNG(h):s_2=h
    
    #Extract the secrect values ID and EPC
    I_D=Protocol_Output_firstsession[3]^s_2^PRNG(N_2)
    E_P_C=N_2^Protocol_Output_firstsession[1]^I_D
 
    
    print("The values for running of the Revised_CG+ protocol",
    " \nSSK<-",I[0]," \nID<-",I[1],"  \ns1<-",I[2],"  \ns2<-",I[3],"  \nN2<-",I[4],"  \nEPC<-",I[5])
    print(" \nThe produced values from the runinng a session","  \nA<-",Protocol_Output_firstsession[0]," \nB<-",Protocol_Output_firstsession[1]," \nE<-",Protocol_Output_firstsession[2]," \nF<-",Protocol_Output_firstsession[3]," \nN1<-",Protocol_Output_firstsession[4])
    print(" \nThe produced values from the runinng next session","  \nA<-",Protocol_Output_secondsession[0]," \nB<-",Protocol_Output_secondsession[1]," \nE<-",Protocol_Output_secondsession[2]," \nF<-",Protocol_Output_secondsession[3]," \nN1<-",Protocol_Output_secondsession[4])
    print('The discovered values for s1 and N2 are', s_1, 'and', N_2, 'that are same as the values for running the protocol')
    print('The discovered values for SSK is', SS_K, 'that are same as the values for running the protocol')
    print('The discovered values for s2 is', s_2, 'that are same as the values for running the protocol')
    print('The discovered values for ID and EPC are', I_D, 'and', E_P_C, 'that are same as the values for running the protocol')
    
    
#All secrect values of CG+ are discovered.
    
