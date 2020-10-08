#os details
a=0;
import os
name = os.name
if(name=="posix"):
   a=a+1
elif(name=="nt"):
    a=a+0.8
else:
    a=a+0.5
if(os.system==0):
    a = a-0.5

#platform type
import platform
release = platform.release()
name = platform.system()
if(name=="Linux"):
    a=a+1
    if(release[0]=='5'):
        a=a+1
    else:
        print("Upgrade OS")
if(name=="Windows"):
    a=a+0.8
    if(release[0]=='1'):
        a=a+0.8
    elif(release[0]=='8'):
        a=a+0.5
    else:
        print("Upgrade OS")
#check for os version
#if windows till 8 decrease score
#if linux check if its stable  version or not

#check ports of the system
import nmap
import sys
nmscan = nmap.PortScanner()
machineip='127.0.0.1'
nmscan.scan(machineip,'100-950')
#check for specific open ports that are open and close
#check if vulnerable ports are closed
openport = []
closedport = []
for host in nmscan.all_hosts():
    print('host: %s (%s)' % (host, nmscan[host].hostname()))
    for proto in nmscan[host].all_protocols():
        print('Protocol: %s' % proto)
        
        lport = nmscan[host][proto].keys()
        sorted(lport)
        for port in lport:
            p = port
            s = nmscan[host][proto][port]['state']
            if(s=='open'):
                openport.append(p)
            else:
                closedport.append(p)
            
if(len(openport)>1):
    print("check ports:",openport)
    a=a+1
else:
    a=a+2
print("System Security Score is:",a)
