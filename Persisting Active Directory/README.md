![image](https://github.com/user-attachments/assets/6d5aa736-4542-468d-bd56-1fc0cfa9b113)
# Persisting Active Directory
Learn about common Active Directory persistence techniques that can be used post-compromise to ensure the blue team will not be able to kick you out during a red team exercise.


TryHackMe room [link](https://tryhackme.com/room/persistingad)


<br>

## Task 1 : Introduction


This room is focusing on Active Directory (AD)  persistence techniques to maintain access even if credentials are rotated. The goal is to learn how to deploy 
persistence methods in AD, including:

  - AD Credentials & DCSync
  - Silver & Golden Tickets
  - AD Certificates
  - Security Identifiers (SIDs)
  - Access Control Lists (ACLs)
  - Group Policy Objects (GPOs)


<br>

First we need to setup the environment..

### 1. Connect to the Network

- If using the AttackBox (web-based):
  - It auto-connects to the network.
![image](https://github.com/user-attachments/assets/6f613807-b675-4a62-a689-8037bc5a41c3)
  - Verify connectivity by pinging THMDC.za.tryhackme.loc.
  - Configure DNS:

        sed -i '1s|^|nameserver 10.200.62.100\n|' /etc/resolv-dnsmasq

    (Replace <THMDC_IP> with the DC's IP from the network diagram.)
  ![image](https://github.com/user-attachments/assets/8422cd53-f7a2-4ff6-811b-b6e57f918be7)

  
  - Test DNS:

        nslookup thmdc.za.tryhackme.loc
    Should resolve to the DC's IP.

- If using your own machine (OpenVPN):
  - Download the .ovpn file from the room's access page.

![image](https://github.com/user-attachments/assets/7ddd7257-2a88-4f79-ba7d-ba4a037bf6c5)
    After succesfull connection, we can verify there..

  - Connect using:

        sudo openvpn persistingad.ovpn

![image](https://github.com/user-attachments/assets/f67dc148-09b1-4201-9c8e-00f0af65ad38)
  
Configure DNS as above at AttackBox.



### 2. Get Initial Credentials
  - Visit:

        http://distributor.za.tryhackme.loc/creds
   
  - Click `Get Credentials` to receive a username & password.

These credentials allow access to `THMWRK1.za.tryhackme.loc` (a jump host).

![image](https://github.com/user-attachments/assets/cdb24921-3c96-410d-8bc6-b5d8260040e2)


### 3. Access the Jump Host

> Via RDP (Remote Desktop):

  - Use RDP client for gui remote access.
  
          xfreerdp3 /v:thmwrk1.za.tryhackme.com /u:tony.wilson /p:Corpus2002 /cert:ignore


> Via SSH (Faster):

  - Use SSH for cli remote access.
    
        ssh za\\tony.wilson@thmwrk1.za.tryhackme.loc



<br>


## Task 2 : Persistence through Credentials

**Objective:**
  We will use Mimikatz to perform a DCSync attack and extract credentials (including NTLM hashes) from the domain controller.

  
