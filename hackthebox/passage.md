<html>
 <body>
  <script src="https://www.hackthebox.eu/badge/148108"></script>
 </body>
 </html>


Back to all write-ups: [here](https://repo4chu.github.io/hackthebox/)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Passage - HackTheBox - WriteUp
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
![Image](https://i.imgur.com/9iTXQiJ.png)

**Tools** utilizadas:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
nmap
exiftool
john
BurpSuite
netcat
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 17:eb:9e:23:ea:23:b6:b1:bc:c6:4f:db:98:d3:d4:a1 (RSA)
|   256 71:64:51:50:c3:7f:18:47:03:98:3e:5e:b8:10:19:fc (ECDSA)
|_  256 fd:56:2a:f8:d0:60:a7:f1:a0:a1:47:a4:38:d6:a8:a1 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Passage News
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=1/6%OT=22%CT=1%CU=37302%PV=Y%DS=2%DC=T%G=Y%TM=5FF5BCD0
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=10A%GCD=1%ISR=10C%TI=Z%CI=I%II=I%TS=A)SEQ(
OS:SP=10A%GCD=2%ISR=10C%TI=Z%II=I%TS=A)OPS(O1=M54DST11NW7%O2=M54DST11NW7%O3
OS:=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11NW7%O6=M54DST11)WIN(W1=7120%W2=7
OS:120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M54DNNSNW
OS:7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF
OS:=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=
OS:%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=
OS:0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RI
OS:PCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 14.778 days (since Tue Dec 22 13:56:06 2020)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=266 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 995/tcp)
HOP RTT       ADDRESS
1   188.90 ms 10.10.14.1
2   189.09 ms passage.htb (10.10.10.206)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Ao acessar a porta 80, nos deparamos com um website.
![Image](https://i.imgur.com/grJc9Zf.png)


Ao analisar o código fonte, podemos perceber que o site está utilizando um CMS chamado 'CuteNews'.
![Image](https://i.imgur.com/ETMGKo8.png)


Acessando o diretório do CMS, encontramos uma página de login e a versão do CuteNews(2.1.2)
![Image](https://i.imgur.com/E6Wa1kL.png)


Como não temos credenciais válidas, vamos tentar realizar a criação de um novo usuário pelo botão de 'Register'
![Image](https://i.imgur.com/ipJ8Q6W.png)


Após conseguirmos o acesso inicial no CMS, podemos encontrar um campo de Upload de arquivos na página de edição do perfil do usuário, portanto, podemos tentar fazer o upload de um arquivo malicioso (:
![Image](https://i.imgur.com/crQgsxz.png)


Tentamos primeiro fazer upload de arquivos em php, porém, não foi possivel subir um arquivo com esta extensão...
Como é um campo de upload de 'Avatar' podemos deduzir que o campo aceitará imagens, então, vamos inserir um código malicioso dentro de nossa imagem. 
Para isso vamos utilizar o exiftool:
![Image](https://i.imgur.com/d4iD8vk.png)

Podemos conferir que conseguimos escrever o comentário dentro da imagem:
![Image](https://i.imgur.com/yECy7Qo.png)

Agora vamos tentar fazer o upload.
Primeiro vamos ligar o BurpSuite para interceptar a requisição
![Image](https://i.imgur.com/SsZQS3v.png)

No burp podemos ver a extensão que está sendo enviada (.jpeg)
![Image](https://i.imgur.com/O2QrZkx.png)

Vamos altera-la para .php e encaminhar a requisição
![Image](https://i.imgur.com/gO1W4Nl.png)

Podemos perceber que a requisição foi bem sucedida

![Image](https://i.imgur.com/0CZunKi.png)

Agora basta acessarmos nosso arquivo para poder executar comandos no servidor, para isso vamos até o diretório de arquivos: http://passage.htb/CuteNews/uploads/avatar_chu_chu.php 
![Image](https://i.imgur.com/AXunvx1.png)

Conseguimos acessar nosso arquivo, agora podemos passar comandos pelo parametro pré definido, em meu caso 'cmd'.
Com isso temos uma execução de código remoto :D
![Image](https://i.imgur.com/RU7sxGJ.png)

Ao pesquisar pelo nc, podemos ver que ele está instalado, portanto, vamos tentar utiliza-lo.
![Image](https://i.imgur.com/5NgSWmB.png)

Vamos abrir uma porta em nossa máquina.
![Image](https://i.imgur.com/55Noqa6.png)

Agora vamos enviar a conexão com o netcat
![Image](https://i.imgur.com/IrydT8Z.png)

![Image](https://i.imgur.com/FswUPdW.png)
w00t, estamos dentro!

Podemos melhorar nossa shell com python para ela se tornar interativa
![Image](https://i.imgur.com/KnYikce.png)




coming soon
