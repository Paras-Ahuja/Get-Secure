#check ports of the system
import nmap
import sys
print("if you want to check your machine's score press y and for other machine in the same network press n")
response = input()
if(response == 'y'):
    machineip='127.0.0.1'
elif(response == 'n'):
    print("Enter private ip of machine in the same network")
    print("Make sure that firewall of your external machine is off")
    machineip = input()
else:
    print("Syntax Error")
try:
    nmscan = nmap.PortScanner()
except nmap.PortScannerError:
    print("Nmap is not installed in this device", sys.exc_info()[0])
    sys.exit(1)
except:
    print("unexpected error", sys.exc_info()[0])
    sys.exit(1)
l=nmscan.scan(machineip,'100-950')
ports=[]
for host in nmscan.all_hosts():
    print('host: %s (%s)' % (host, nmscan[host].hostname()))
    for proto in nmscan[host].all_protocols():
        print('Protocol: %s' % proto)
        print("---------------------------------------------")
        
        lport = nmscan[host][proto].keys()
        sorted(lport)
        for port in lport:
            print ('port : %s\tstate : %s' % (port, nmscan[host][proto][port]['state']))
            ports.append(port)
print("---------------------------------------------")
print()
print()
print("Find detailed port information below")
print()
for i in l.values():
    for j in i.values():
        print(j)
print()
print()
if(len(ports)==0):
    print("All ports are filtered")
    print("If deep port scan needed turn off your firewall and check again")
    
