# CG+ RFID Authentication Protocol: A Passive-Disclosure-Attack and An Improvement

Python Implementation of a Passive Disclosure Attack against a lightweight Authentication Protocol for VANETs.

RFID system utilizes radio frequency to transmit information among Tags and Readers which adversary can effortlessly listened the information over the wireless channel. In this regard, advanced authentication protocols have been proposed with their focus on lightweight computations while preserving strong security. Recently, an revised version of RFID protocol suitable for VANETs that is called CG+ presented and the authors acclaimed that the protocol is robust against security and privacy attacks [1]. However, in this Python code, presenting a passive disclosure attack with the complexity of O(2^16) that discloses all secret parameters of the CG+, we show that this protocol fails to provide the claimed level of security. Moreover, we inhibit mentioned shortcoming via applying some minor modifications to present an EPC-C1G2 RFID authentication protocol, so that it satisfies the optimal security bound. 

The presented attack against modified version of the protocol shows that the complexity of the attack is not lower than the claimed security level of the EPC-C1G2 standard.


[1]. Moradi, F., Mala, H., and Ladani, B. T. (2015). Security Analysis and Strengthening of an RFID Lightweight Authentication Protocol Suitable for VANETs. Springer, Wireless Personal Communications, 83(4), pp. 2607-2621.


# By considerig following values to run the protocol, code outputs discovered parameters. 
SSK<- 7225  
ID<- 49347   
seed<- 13498   
N2<- 51653
 
out-put:
A<- 46946  
B<- 2310  
C<- 39348  
N1<- 23852
The discovered value for s is 13498 that is same as the produced seed.
The discovered value for N2 is 58842 that is same as the value for running the protocol.
The discovered values for ID and SSK are 60636 , 30535 that are same as the values for running the protocol.

