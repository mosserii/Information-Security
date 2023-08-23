### **Firewalls and Stealth communication**

In this exercise, we use 
Q1:
1. Stealth SYN scan - check whether some TCP ports are open, closed or filtered by a firewall, by sending them a SYN and receiving SYN/ACK, a RST or Nothing.
2. A simple host-based FIREWALL that records the number of SYNs received from each IP, and if the number of SYNs in the last 60 seconds exceeds 15, block that IP using iptables.
3. Explanation why this firewall is really simple and has a vulnerability - An attacker can send many SYN (SYN spoofing) and use many differnet src IP ("fake ones") and because this firewall is stateful, there will be a DoS after some time.
4. Fix the problem, make every port look open and by that render the scan useless.

Q2 :
1. Spying - track TCP packets containing the word "love" and adds the sender's IP to the unpersons set.
2. Encryption - encrypt the messages in order to avoid the spying and then decrypt them.
3. Detecting encryption - detect if the message is encrypted by using Shannon's Entropy.
4. Stealth communication - hide data in the TCP metadata.