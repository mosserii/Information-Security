### **Network Vulnerabilities using Scapy and Wireshark**

For this exercise, we added another mini machine that is connected to the same NAT Network as our normal VM.



Q1: 
Using Wireshark(!) in order to record (sniif) packets sent over the local network, especially ones that go to HTTP (port 80). 
- we see how one can record these packets and see their content : 
- The usual machine is recording traffic while the little one is using the course website and trying to login, we parsed the packet and got the username and password (you can try, these are not my real details ;)).
(see more in q1.py and q1.txt).

Q2 : 
Redirecting every attempt to access the course website, to Instagram website!!
- check if there is an attempt to the course website.
- return a IP/TCP packet with the instagram address. 
(see more in q2.py and q2.txt).

Q3 : 
Redirecting all of the traffic of the victim through our own machine.
Using ARP poisining so we fool the victim so he thinks we are his gateway dest_address.
(see more in q3.py and q3.txt).