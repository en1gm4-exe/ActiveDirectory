![image](https://github.com/user-attachments/assets/8c62fb6d-1a39-4cae-829a-fbc79354a3a7)

 # Enumerating Active Directory
This room covers various Active Directory enumeration techniques, their use cases as well as drawbacks.

TryHackMe room [link](https://tryhackme.com/room/adenumeration)

<br>
<br>

## Task 1 : Why AD Enumeration
   Once we have that first set of AD credentials and the means to authenticate with them on the network, a whole new world of possibilities opens up! We can start enumerating various details about the AD setup and structure with authenticated access, even super low-privileged access.

   
   During a red team engagement, this will usually lead to us being able to perform some form of privilege escalation or lateral movement to gain additional access until we have sufficient privileges to execute and reach our goals. In most cases, enumeration and exploitation are heavily entwined. Once an attack path shown by the enumeration phase has been exploited, enumeration is again performed from this new privileged position, as shown in the diagram below.

![image](https://github.com/user-attachments/assets/c5023ab4-4c68-432f-bc2f-c6f752b4f2f1)


> Start...

 To start with we started the network and our Network diagram looks like this

![image](https://github.com/user-attachments/assets/69048d28-730d-4b79-9590-ae3377fc4778)

> Attack machine.. 
First we need to configure DNS on our attack machine to use the DC (10.200.56.101 as per your network diagram). For this , we add this into our configuration file to resolve the DNS calls...
   
    sed -i '1s|^|nameserver 10.200.56.101\n|' /etc/resolv.conf

After this we can verify the if the DNS wokring fine or not 
  
    nslookup thmdc.za.tryhackme.com


<pre>
Server:         10.200.56.101
Address:        10.200.56.101#53

Name:   thmdc.za.tryhackme.com
Address: 10.200.56.101
</pre>

  
Now, as all done, we need to visit   `http://distributor.za.tryhackme.com/creds` where we can find the credentials to login as a remote user..
![image](https://github.com/user-attachments/assets/addefc95-8e41-49a0-948e-e7d062db4839)

> Remote Connection..

 After getting the credential, I was able to login through `ssh`
  
      ssh za.tryhackme.com\\arthur.campbell@thmjmp1.za.tryhackme.com
      
![image](https://github.com/user-attachments/assets/977a7180-a955-4e42-8d22-08f3b693e617)

and similarlly, I connected through `RDP`

    xfreerdp3 /v:thmjmp1.za.tryhackme.com /u:arthur.campbell /p:Pksp9395 /cert:ignore
    
![image](https://github.com/user-attachments/assets/21d578cc-7cab-44ac-896d-bbe838777d7b)

<br>

## Task 2 : Credential Injection

### Windows vs Linux for AD Enumeration:

- While Kali Linux can perform AD enumeration, a Windows machine is essential for in-depth analysis and mimicking real attack scenarios.
- Windows built-in tools like `runas.exe` allow credential injection for network authentication.

<br>

### Runas for Credential Injection:

Command:
    
      runas.exe /netonly /user:<domain>\<username> cmd.exe

Parameters:
  
  - `/netonly` – Uses credentials only for network connections (not local auth).
  - `/user` – Specifies the domain and username (preferably FQDN).
  - `cmd.exe` – Spawns a new command prompt with injected credentials.

No immediate DC verification; passwords are accepted without validation.

<br>

### Verifying Credentials:

Check if credentials work by accessing `SYSVOL` (a shared AD folder readable by any domain user):

    
    dir \\<domain>\SYSVOL\

Requires proper DNS configuration (pointing to the Domain Controller).

<br>

### DNS Configuration:
We can set DNS manually if DHCP/VPN doesn’t auto-configure:

    $dnsip = "<DC IP>"
    $index = Get-NetAdapter -Name 'Ethernet' | Select-Object -ExpandProperty 'ifIndex'
    Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $dnsip

<br>  

### Verify DNS with nslookup za.tryhackme.com.

 > Hostname vs IP Authentication:
   - Hostname (e.g., za.tryhackme.com) → Uses `Kerberos` authentication.
   - IP Address → Forces `NTLM authentication` (useful for stealth in Red Teaming to avoid OverPass/Pass-The-Hash detection).

<br>

### Using Injected Credentials:
Any network communication from the spawned cmd.exe uses the injected credentials.

Works with:

  - `MS SQL` (Windows Authentication mode).
  - `Web apps` using NTLM authentication.
  - Other AD-dependent services.

> Why This Matters:

- Enables attackers to leverage stolen credentials without needing a domain-joined machine.
- Facilitates deeper AD enumeration and exploitation from a non-domain Windows host.
- Understanding authentication methods (`Kerberos` vs. `NTLM`) helps evade detection.
- This technique is foundational for later AD enumeration tasks, such as querying `SYSVOL` or interacting with AD services.


<br>

## _Answers_

1. What native Windows binary allows us to inject credentials legitimately into memory?    

       runas.exe
     
3. What parameter option of the runas binary will ensure that the injected credentials are used for all network connections?

        /netonly

4. What network folder on a domain controller is accessible by any authenticated AD account and stores GPO information?

         SYSVOL
   
5. When performing dir \\za.tryhackme.com\SYSVOL, what type of authentication is performed by default?

        Kerberos Authentication

<br>

## Task 3 : Enumeration through Microsoft Management Console

For enumeratoin through `MMC`(Microsoft Management Console) , we need to setup following configuration/changes in our :

- Connect to THMJMP1 via RDP using provided credentials.
- `MMC + RSAT` AD Snap-Ins are pre-installed on THMJMP1.
- For personal Windows machines: (_NOT REQUIRED IN THIS LAB._)
   Install via: `Apps & Features` → Manage Optional Features → Add `RSAT: Active Directory Domain Services and Lightweight Directory Tools`.


As for use , we already have remote connection(RDP/SSH), so we will use the injected CMD (from runas /netonly) to launch MMC:

    mmc.exe

![image](https://github.com/user-attachments/assets/bfeb774e-4eb8-45c0-9cd9-3c8bf6e5f08d)

By clicking on this, we can launch the console..

Now, it's time to add AD Snap-ins, 
- for this goto `File` → `Add/Remove Snap-in` → `Add`
- Select and add these snap-ins:
  1. Active Directory Users and Computers
  2. Active Directory Sites and Services
  3. Active Directory Domains and Trusts

![image](https://github.com/user-attachments/assets/b599c645-58b1-4b7f-b8b4-8a1d6b68ac64)


- Configure each to point to za.tryhackme.com:
  
     Right-click each `snap-in` → `Change Domain/Forest` → Enter `za.tryhackme.com`.

![image](https://github.com/user-attachments/assets/8168aae9-16ec-4a1c-bca8-91aefb222260)


Next, we need to enable Advanced Features
 - Right-click `Active Directory Users and Computers` → `View` → `Advanced Features`.



<br>

## _Answers_

1. How many Computer objects are part of the Servers OU?

       2
  
For this we have to navigate to `Active Directory Users and Computers` → `za.tryhackme.com` → `Servers`  and we can count the listed  Computer objects..  i.e. `2` in our case
![image](https://github.com/user-attachments/assets/11af6719-9e0f-4200-9312-169ae4c191fa)



2. How many Computer objects are part of the Workstations OU?

       1

For this we have to navigate to `Active Directory Users and Computers` → `za.tryhackme.com` → `Workstations`  and we can count the listed  Computer objects..  i.e. `1` in our case
![image](https://github.com/user-attachments/assets/c6873f80-3790-4ef2-a205-a910a978880d)


4. How many departments (Organisational Units) does this organisation consist of?

       7

For this we have to navigate to `Active Directory Users and Computers` → `za.tryhackme.com` → `People`  and we can count the listed  departments..  i.e. `7` in our case
![image](https://github.com/user-attachments/assets/ca6535db-5777-401b-918e-7e34eb915b36)


5. How many Admin tiers does this organisation have?

       3 

For this we have to navigate to `Active Directory Users and Computers` → `za.tryhackme.com` → `Admins`  and we can count the tiers..  i.e. `T0`,`T1` and `T2` in our case
![image](https://github.com/user-attachments/assets/bf1609d5-9453-4c15-843d-de6e7eb503ee)


6. What is the value of the flag stored in the description attribute of the t0_tinus.green account?

       THM{Enumerating.Via.MMC}
 
For this, I simply looked into T0,  `t0_tinus.green` was there and then `Right-click` on it and click on `Properties` and we can find the flag in the `description` attribute. 

![image](https://github.com/user-attachments/assets/6c4fc3dc-9ff9-488b-873b-53f175652ce7)

<br>


## Task 4 : Enumeration through Command Prompt

There are times when you just need to perform a quick and dirty AD lookup, and Command Prompt has your back. `Good ol'` reliable CMD is handy when you perhaps don't have RDP access to a system, defenders are monitoring for PowerShell use, and you need to perform your AD Enumeration through a `Remote Access Trojan` (RAT). It can even be helpful to embed a couple of simple AD enumeration commands in your phishing payload to help you gain the vital information that can help you stage the final attack.


`CMD` has a built-in command that we can use to enumerate information about AD, namely `net`. The `net` command is a handy tool to enumerate information about the local system and AD. We will look at a couple of interesting things we can enumerate from this position, but this is not an exhaustive list.

1. Enumerate All Domain Users

       net user /domain

This command lists all AD user accounts in the domain.



2. Get Detailed User Info

       net user <username> /domain
   
This shows account status, password last set, group memberships (limited to 10 groups), and logon restrictions.



3. List All Domain Groups

       net group /domain

This reveals security groups (e.g., Domain Admins, Tier 1 Admins).


4. Check Group Membership

       net group "<Group Name>" /domain

This lists members of a specific group (e.g., net group "Tier 1 Admins" /domain).


5. View Password Policy


       net accounts /domain
   
This displays password rules:
  - Minimum/maximum password age.
  - Lockout threshold & duration.
  - Password history & length requirements.

### Use Cases
- **Quick Recon:** Fast way to gather AD details without external tools.
- **Phishing Payloads:** Can be embedded in `VBScript`/`macros` for initial intel.
- **Low-Profile Attacks:** Often overlooked by defenders compared to PowerShell.


<br>

## _Answers_

1. Apart from the Domain Users group, what other group is the aaron.harris account a member of?

       Internet Access

For this we need to use follwing command..

      net user aaron.harris /domain
   
   This will list the details of the user and we need to check Group memberships attribute and we can find out our answer..

 ![image](https://github.com/user-attachments/assets/115ec4d4-c792-4df6-b3d4-7ead9db29a40)

   

3. Is the Guest account active? (Yay,Nay)

       Nay

   By looking at the output of the  follwoing command we can tell user status..

       net user guest /domain
       
  If "Account active" is `Yes` then it is `Yay` and `Nay` if "Account active" is `No`.
![image](https://github.com/user-attachments/assets/6e07ee66-7a06-4c8b-8a4e-35e5ffca2d88)



4. How many accounts are a member of the Tier 1 Admins group?

       7       

 By using the following command, we can find the names of all the users..

       net group "Tier 1 Admins" /domain

![image](https://github.com/user-attachments/assets/e06e1790-d359-4960-aa16-7aa11f957817)


5. What is the account lockout duration of the current password policy in minutes?

       30

For find out the lockout duration policy, I used the following command...

       net accounts /domain
   
![image](https://github.com/user-attachments/assets/a9372efb-acca-4b64-80bf-82b7eade8f17)


<br>


## Task 5 : Enumeration through PowerShell

PowerShell is the upgrade of Command Prompt. Microsoft first released it in 2006. 
While PowerShell has all the standard functionality Command Prompt provides, it also 
provides access to cmdlets (pronounced command-lets), which are .NET classes to perform 
specific functions. While we can write our own cmdlets, like the creators of PowerView did, 
we can already get very far using the built-in ones.

### Some commmon commands..

1. Enumerate Users

 - List a Specific User:

       Get-ADUser -Identity gordon.stevens -Server za.tryhackme.com -Properties *
   
Shows all attributes (e.g., Description, LastLogon, group memberships).

 - Search Users with Filters:

       Get-ADUser -Filter 'Name -like "*stevens"' -Server za.tryhackme.com | Format-Table  Name,SamAccountName

2. Enumerate Groups

 - List Group Details:

       Get-ADGroup -Identity "Administrators" -Server za.tryhackme.com

 - List Group Members:

       Get-ADGroupMember -Identity "Tier 1 Admins" -Server za.tryhackme.com

3. Search AD Objects
 - Find Modified Objects (e.g., after a date):

       $ChangeDate = New-Object DateTime(2022, 02, 28, 12, 00, 00)
       Get-ADObject -Filter 'whenChanged -gt $ChangeDate' -Server za.tryhackme.com

 - Find Accounts with Failed Logins (for password spraying avoidance):
    
       Get-ADObject -Filter 'badPwdCount -gt 0' -Server za.tryhackme.com


4. Domain Information

       Get-ADDomain -Server za.tryhackme.com

    Reveals domain structure, containers (e.g., UsersContainer, DomainControllersContainer).

5. Modify AD Objects (Example: Password Reset)

       Set-ADAccountPassword -Identity gordon.stevens -OldPassword (ConvertTo-SecureString "old" -AsPlainText -Force) -NewPassword (ConvertTo-SecureString "new" -AsPlainText -Force) -Server za.tryhackme.com



<br>

## _Answers_

1. What is the value of the `Title` attribute of Beth Nolan (`beth.nolan`)?

       senior


For this we will use following command, it will give use the value of the title..

     Get-ADUser -Identity beth.nolan -Server za.tryhackme.com -Properties Title | Select-Object Title

![image](https://github.com/user-attachments/assets/396ad168-f843-4914-9532-72f58adb2ba7)




2. What is the value of the `DistinguishedName` attribute of Annette Manning (`annette.manning`)?
     
       CN=annette.manning,OU=Marketing, OU=People, DC=za, DC=tryhackme,DC=com
   
For this we will be using the following command to find the value for DistinguishedName..

       Get-ADUser -Identity annette.manning -Server za.tryhackme.com -Properties DistinguishedName | Select-Object DistinguishedName
   
![image](https://github.com/user-attachments/assets/ef7f270c-4fdd-4707-b845-69711420fc03)




3. When was the `Tier 2` Admins group created?

       2/24/2022 10:04:41 PM

Using the following command , we can see the time where the admin was created...

       Get-ADGroup -Identity "Tier 2 Admins" -Server za.tryhackme.com -Properties Created | Select-Object Created

![image](https://github.com/user-attachments/assets/8dc3612a-6a22-43c7-9b14-974969c15b13)



4. What is the value of the `SID` attribute of the Enterprise Admins group?
 
       S-1-5-21-3330634377-1326264276-632209373-519


 For finding the `SID` value for Enterprise Admins group, we can see the output of the following command

        Get-ADGroup -Identity "Enterprise Admins" -Server za.tryhackme.com -Properties SID | Select-Object SID
        
![image](https://github.com/user-attachments/assets/4ac03d14-e1ab-486a-96b5-5762a1dc78e9)


5. Which container is used to store deleted AD objects?

       CN=Deleted Objects,DC=za,DC=tryhackme,DC=com

For find out the container, we can see the following command..
    
     Get-ADDomain -Server za.tryhackme.com | Select-Object DeletedObjectsContainer
   
![image](https://github.com/user-attachments/assets/c0d433a5-cdc1-4aae-aa5e-73e3a25157b0)




<br>



## Task 6 : Enumeration through Bloodhound

We will be using the following tools...
  
  - `Bloodhound`: GUI tool that visualizes Active Directory attack paths using graph theory.
  - `Sharphound`: Data collector for Bloodhound (runs on the target network).
  - `Neo4j`: Database backend that powers Bloodhound.




![image](https://github.com/user-attachments/assets/cc00cfab-6ba8-4e8a-a298-a0a6e75890ab)

![image](https://github.com/user-attachments/assets/44642be4-26ae-4a50-bb6e-a572aa2abd54)

<br> 

## _Answers_


1. What command can be used to execute Sharphound.exe and request that it recovers Session information only from the za.tryhackme.com domain without touching domain controllers?

     To start with, we will use the `Sharphound` and For this we will use the follwoign command to

- collect only session data (noisy but lightweight).
- Avoids domain controllers (`--ExcludeDCs`).

       SharpHound.exe --CollectionMethods Session --Domain za.tryhackme.com --ExcludeDCs

![image](https://github.com/user-attachments/assets/c1dee5ee-e3f3-4ea6-9128-84d170201665)



 Once we retirve the zip file we need to drag it into the bloodhound where we can found the rest of the answers..

         scp za.tryhackme.com\\arthur.campbell@thmjmp1.za.tryhackme.com:C:/Users/arthur.campbell/Documents/202*.zip .
 
2. Apart from the krbtgt account, how many other accounts are potentially kerberoastable?

        4
  
4. How many machines do members of the Tier 1 Admins group have administrative access to?

       2 

5. How many users are members of the Tier 2 Admins group?

       15


<br> 


## Task 7 : Conclusion

### Core Enumeration Techniques Covered:
- `Microsoft Management Console` (MMC) – GUI-based AD exploration using RSAT tools.
- `Command Prompt` (net commands) – Quick user/group/policy checks (e.g., net user /domain).
- `PowerShell` (AD-RSAT) – Advanced queries (e.g., Get-ADUser, Get-ADGroup).
- `Bloodhound/Sharphound` – Visual attack path mapping via graph theory.

### Additional Enumeration Methods
- LDAP Queries: Directly query DCs for AD objects (e.g., users, groups).
- PowerView: Legacy but powerful PowerShell script for manual AD recon.
- WMI (root\directory\ldap): Retrieve AD data via Windows Management Instrumentation.

### Why Enumeration Matters
- **Understand AD Structure:** Identify users, groups, OUs, and trust relationships.
- **Find Attack Paths:** Discover privilege escalation routes (e.g., misconfigured ACLs, nested groups).
- **Plan Exploits:** Use data to stage targeted attacks (e.g., `Kerberoasting`, `lateral movement`).


### Mitigation Strategies
- **Detect Anomalies:**
  - Monitor mass LogOn events (e.g., Sharphound’s session enumeration).
  - Block/alert on unauthorized `PowerShell`/`CMD` usage.

- **Tool Signatures:**
  - Flag `Sharphound` binaries or RSAT tooling on non-admin systems.

- **Proactive Defense:**
  - Blue teams should regularly audit AD using the same tools to fix misconfigurations.


### Next Steps
- `Privilege Escalation`: Exploit weak permissions (e.g., overly permissive groups).
- `Lateral Movement`: Move from low-value to high-value targets (e.g., workstations → DCs).

