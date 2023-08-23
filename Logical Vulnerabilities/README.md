### **Logical Vulnerabilities**

In this exercise, we find logical vulnerabilities in the code so that we can exploit them and use the code not in the way the programmer planned to use it.

Q1 : 
Code injection - the function validate_script in run.py is using eval, therefore it can execute input from user. POC : os.system('echo hacked').

Q3 :
I noticed that in run.py, it checks if user[:username_end] == data[:username_end], the problem is that we can affect username_end size, if we set it to 0 so
every string of size 0 is equals to a string of size 0.

Q4 : 
Exporting Unsafe using of json in authentication.

Q5 : 
TOCTTOU + long calculations - here there was not an obvious vulnerability. Exploiting the fact that the we can send it the actual file (example.json) that will be validated,
and once we know that in run.py, we arrived already to the verify function (say after 3 seconds),
we can change the json file dynamically using Subprocess!!