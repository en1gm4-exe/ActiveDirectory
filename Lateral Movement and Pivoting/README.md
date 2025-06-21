![image](https://github.com/user-attachments/assets/1391962a-d763-4261-9809-b61707c31bc1)


# Lateral Movement and Pivoting
   Learn about common techniques used to move laterally across a Windows network.
   

TryHackMe room [link](https://tryhackme.com/room/lateralmovementandpivoting)


## Task 1 : Introduction

> Key Objectives

- Learn **lateral movement techniques** used by attackers to navigate networks stealthily.
- Use stolen **credentials/authentication** material to move between systems.
- **Pivot** through compromised hosts to access restricted segments.




> Network Setup Guide

1. DNS Configuration (Critical for AD)

   > Attack Machine:

        sed -i '1s|^|nameserver $THMDCIP\n|' /etc/resolv-dnsmasq  # Replace $THMDCIP with DC’s IP

      And to verify the connection run..

       nslookup thmdc.za.tryhackme.com  # Verify DNS resolution
   
     Set DNS to THMDC’s IP in Network Manager.


2. VPN Connection (For Personal Machines)

       sudo openvpn user-lateralmovementandpivoting.ovpn

Verify connection on the access page (green tick).

3. Note Your Attacker IP

        ifconfig                   

We will be using this IP for reverse shells/payloads..
