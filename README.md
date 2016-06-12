#BroIDS_Unicorn

simple plugin to detect shellcode on Bro IDS with Unicorn

**install bro:**

https://www.bro.org

**install unicorm-engine:**

https://github.com/unicorn-engine/unicorn

##Vuln server:

**new terminal run bro:**

bro -i eth0 bro/detector.bro

**new terminal run unicorn:**

python bro/checkshell.py

**run vuln service:**

cd vulnserver 

./socat.sh vuln

##client

`change ip -> vuln server`

**run exploit**

python exploit_code/pwn.py

##Video demo

https://youtu.be/0nd1XJ9I4pQ
