# simple_BroIDS_Unicorn#install bro at:
https://www.bro.org
#install unicorm-engine at:
https://github.com/unicorn-engine/unicorn

###Vuln server:
#run bro: 
bro -i eth0 bro/detector.bro
#run unicorn: 
python bro/checkshell.py
#run vuln
chmod +x bro/socat.sh
./bro/socat.sh

###client
#change ip -> vuln server
python exploit_code/pwn.py
