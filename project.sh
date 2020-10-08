#!/bin/bash
figlet -f big "Get Secure  by Paras Ahuja"
echo "Enter 1 for Network Intrusion Detection System and check for connection"
echo "Enter 2 to check security score of your System"
echo "Enter 3 to get port details of your or any system in network(You should have its IP address)"
read num
if [ $num == 1 ]
then
	figlet -f big "    ==N I D S==              by Paras Ahuja"
	python nids.py
fi
if [ $num == 2 ]
then
	figlet -f big "==Security Score==              "
	python3 "security score.py"
fi
if [ $num == 3 ]
then
	figlet -f big "==Port Scanner==              "
	python3 "port check.py"
fi


