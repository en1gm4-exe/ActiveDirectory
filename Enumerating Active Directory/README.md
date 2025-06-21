


Task : 1
Network Diagram
![image](https://github.com/user-attachments/assets/69048d28-730d-4b79-9590-ae3377fc4778)

 
Configure DNS on your attack machine to use the DC (10.200.56.101 as per your network diagram)

First we add this into our configuration file to resolve the DNS calls.
   
    sed -i '1s|^|nameserver 10.200.56.101\n|' /etc/resolv.conf

After this we can verify the if the DNS wokring fine or not 
  
    nslookup thmdc.za.tryhackme.com


<pre>
Server:         10.200.56.101
Address:        10.200.56.101#53

Name:   thmdc.za.tryhackme.com
Address: 10.200.56.101
</pre>
  
Now, as all done, we need to visit           http://distributor.za.tryhackme.com/creds
for the credentials i.e.
![image](https://github.com/user-attachments/assets/addefc95-8e41-49a0-948e-e7d062db4839)


After getting the credential i was able to login through ssh
  
      ssh za.tryhackme.com\\arthur.campbell@thmjmp1.za.tryhackme.com
      
![image](https://github.com/user-attachments/assets/977a7180-a955-4e42-8d22-08f3b693e617)

and similarlly, rdp usuing command

    xfreerdp3 /v:thmjmp1.za.tryhackme.com /u:arthur.campbell /p:Pksp9395 /cert:ignore
    
![image](https://github.com/user-attachments/assets/21d578cc-7cab-44ac-896d-bbe838777d7b)



## Task 2 : Credential Injection

### Windows vs Linux for AD Enumeration:

- While Kali Linux can perform AD enumeration, a Windows machine is essential for in-depth analysis and mimicking real attack scenarios.
- Windows built-in tools like runas.exe allow credential injection for network authentication.

<br>

### Runas for Credential Injection:

Command:
    
      runas.exe /netonly /user:<domain>\<username> cmd.exe

Parameters:
  
  - /netonly – Uses credentials only for network connections (not local auth).
  - /user – Specifies the domain and username (preferably FQDN).
  - cmd.exe – Spawns a new command prompt with injected credentials.

No immediate DC verification; passwords are accepted without validation.

<br>

### Verifying Credentials:

Check if credentials work by accessing SYSVOL (a shared AD folder readable by any domain user):

    
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

- Hostname vs IP Authentication:
  Hostname (e.g., za.tryhackme.com) → Uses Kerberos authentication.
  IP Address → Forces NTLM authentication (useful for stealth in Red Teaming to avoid OverPass/Pass-The-Hash detection).

<br>

### Using Injected Credentials:
Any network communication from the spawned cmd.exe uses the injected credentials.

Works with:

  - MS SQL (Windows Authentication mode).
  - Web apps using NTLM authentication.
  - Other AD-dependent services.

> Why This Matters:

- Enables attackers to leverage stolen credentials without needing a domain-joined machine.
- Facilitates deeper AD enumeration and exploitation from a non-domain Windows host.
- Understanding authentication methods (Kerberos vs. NTLM) helps evade detection.
- This technique is foundational for later AD enumeration tasks, such as querying SYSVOL or interacting with AD services.


<br>

## _Answers_
1. What native Windows binary allows us to inject credentials legitimately into memory?        runas.exe

       runas.exe
     
3. What parameter option of the runas binary will ensure that the injected credentials are used for all network connections?

        /netonly

4. What network folder on a domain controller is accessible by any authenticated AD account and stores GPO information?

         SYSVOL
   
5. When performing dir \\za.tryhackme.com\SYSVOL, what type of authentication is performed by default?

        Kerberos Authentication
