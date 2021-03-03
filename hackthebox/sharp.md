<html>
 <body>
  <script src="https://www.hackthebox.eu/badge/148108"></script>
 </body>
 </html>


Back to all write-ups: [here](https://repo4chu.github.io/hackthebox/)


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Sharp - HackTheBox - WriteUp
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
![image](https://i.imgur.com/b8fWlNj.png)

**Tools** utilizadas:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
nmap
smbclient
rpcclient
ExploitRemotingService
ysoserial
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
PORT     STATE SERVICE            VERSION
135/tcp  open  msrpc              Microsoft Windows RPC
139/tcp  open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
8888/tcp open  storagecraft-image StorageCraft Image Manager
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host


Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-12-08T12:21:23
|_  start_date: N/A

TRACEROUTE (using port 8888/tcp)
HOP RTT       ADDRESS
1   224.18 ms 10.10.14.1
2   224.76 ms 10.10.10.219
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
smbclient -L \\10.10.10.219 -N
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
![Image](https://i.imgur.com/Fvm7tk6.png)

Vamos ao diretório kanban
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
smbclient -L \\10.10.10.219\\kanban -N
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
![Image](https://i.imgur.com/yIbnT0B.png)

Podemos ver um arquivo chamado PortableKanban.pk3.bak que apararente ser um arquivo de backup, então vamos lê-lo
![Image](https://i.imgur.com/wWij6x7.png)

Ao abri-lo, podemos ver que, dentro do arquivo existem senhas criptografadas:
![Image](https://i.imgur.com/m4DVEag.png)

Começamos acessando o serviço SMB para copiar o programa para nossa maquina:

![Image](https://i.imgur.com/Wkz1IMK.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
smbclient \\\\10.10.10.219\\kanban -N
get pkb.zip
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Essa máquina, pela primeira vez tive que criar uma máquina Windows para usar como atacante...
Extraímos os arquivos do nosso arquivo pkb.zip
![Image](https://i.imgur.com/u7nyOBw.png)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Ao executarmos o arquivo PortableKanban.exe podemos perceber que ele faz a criação do arquivo PortableKanban.pk3.bak onde ele guarda as credenciais...
Então vamos substituir pelo arquivo PortableKanban.pk3.bak que encontramos em nosso alvo.

Ao substituir o arquivo PortableKanban.pk3.bak, precisamos de credenciais para conseguir acessar o programa.

![Image](https://i.imgur.com/q1UFNLT.png)

![Image](https://i.imgur.com/GSP4UQv.png)

O que podemos fazer é tentar editar o arquivo que guarda as senhas para acessar~








if i helped you, add + respect at my profile :D
<html>
 <body>
  <script src="https://www.hackthebox.eu/badge/148108"></script>
 </body>
 </html>
 
my references
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
x
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
