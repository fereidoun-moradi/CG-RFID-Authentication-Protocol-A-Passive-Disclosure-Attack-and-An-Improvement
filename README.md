# CG+-RFID-Authentication-Protocol-A-Passive-Disclosure-Attack-and-An-Improvement

Implementation of a Passive Disclosure Attack on a lightweight Authentication Protocol for VANETs.

RFID system utilizes radio frequency to transmit information among Tags and Readers which adversary can effortlessly listened the information over the wireless channel. In this regard, advanced authentication protocols have been proposed with their focus on lightweight computations while preserving strong security. Recently, an revised version of RFID protocol suitable for VANETs that is called CG+ presented and the authors acclaimed that the protocol is robust against security and privacy attacks [1]. However, in this Python code, presenting a passive disclosure attack with the complexity of O(216) that discloses all secret parameters of the CG+, we show that this protocol fails to provide the claimed level of security. Moreover, we inhibit mentioned shortcoming via applying some minor modifications to present an EPC-C1G2 RFID authentication protocol, so that it satisfies the optimal security bound. 

The presented attack against modified version of the protocol shows that the complexity of the attack is not lower than the claimed security level of the EPC-C1G2 standard.


[1]. Moradi, F., Mala, H., and Ladani, B. T. (2015). Security Analysis and Strengthening of an RFID Lightweight Authentication Protocol Suitable for VANETs. Springer, Wireless Personal Communications, 83(4), pp. 2607-2621.

