<html>
 <body>
  <script src="https://www.hackthebox.eu/badge/148108"></script>
 </body>
 </html>


Back to all write-ups: [here](https://repo4chu.github.io/hackthebox/)


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Spectra - HackTheBox - WriteUp
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
![image](https://i.imgur.com/HsXjN7y.png)

**Tools** utilizadas:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
nmap
ffuf
metasploit
python
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.1 (protocol 2.0)
| ssh-hostkey: 
|_  4096 52:47:de:5c:37:4f:29:0e:8e:1d:88:6e:f9:23:4d:5a (RSA)
80/tcp   open  http    nginx 1.17.4
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.17.4
|_http-title: Site doesn't have a title (text/html).
3306/tcp open  mysql   MySQL (unauthorized)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=2/27%OT=22%CT=1%CU=35715%PV=Y%DS=2%DC=T%G=Y%TM=603AA18
OS:D%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=107%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST1
OS:1NW7%O6=M54DST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Após nosso scan no nmap, podemos perceber um serviço HTTP em nosso alvo.
![Image](https://i.imgur.com/AXnKt2h.png)

Ao acessar nos deparamos com essa página:

![Image](https://i.imgur.com/5KTYuZG.png)

O primeiro link, nos envia para o diretório /main/ que está rodando um site WordPress 5.4.2
![Image](https://i.imgur.com/7H6BjiB.png)

No segundo link, recebemos um erro de falha ao conectar na database:
![Image](https://i.imgur.com/hvDZvvw.png)

Porém, se tentarmos listar o diretório:

![Image](https://i.imgur.com/vRDHkb3.png)

Um desses arquivo chama atenção, wp-config.php.save mas se tentarmos lê-lo:
![Image](https://i.imgur.com/iUOTXqF.png)

Nesse ponto usamos o truque de visualizar o código fonte da página:
![Image](https://i.imgur.com/esPgN4m.png)

E então temos credenciais :D~
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
define( 'DB_NAME', 'dev' );
define( 'DB_USER', 'devtest' );
define( 'DB_PASSWORD', 'devteam01' );
define( 'DB_HOST', 'localhost' );
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Se tentarmos acessar a página de login do site WordPress, percebemos que as credenciais não funcionam...
![Image](https://i.imgur.com/ji0R1jc.png)

Ao continuar analisando o site WordPress, podemos perceber que o nome do usuário é 'administrator'
![Image](https://i.imgur.com/vRSHfYy.png)

Então, vamos tentar logar com as credenciais administrator:devteam01
eee b00m, estamos dentro ~
![Image](https://i.imgur.com/1d6rYmk.png)

Agora vamos utilizar o metasploit para criar uma conexão reversa com a máquina, para isso vamos usar o exploit: 
![Image](https://i.imgur.com/FQIZS2a.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
exploit/unix/webapps/wp_admin_shell_upload
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Ajustamos as opções:

![Image](https://i.imgur.com/WFpoNvj.png)

Conferimos antes de executar:
![Image](https://i.imgur.com/LzDMsC5.png)

Após isso executamos nosso exploit e ganhamos nosso acesso:
![Image](https://i.imgur.com/uN7E8wF.png)

Após isso, em nossa máquina geramos uma chave RSA para escalarmos nosso acesso:
![Image](https://i.imgur.com/YUHgUGr.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ssh-keygen
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

No meterpreter, pedimos uma shell e escrevemos nossa chave RSA no arquivo /home/nginx/.ssh/authorized_keys para melhorarmos nossa shell.
![Image](https://i.imgur.com/JOhbtVl.png)

Após escreve-la, realizamos a conexão via SSH.
![Image](https://i.imgur.com/hlvKakv.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ssh nginx@spectra.htb -i nginx
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Agora que temos uma shell interativa, começamos a mapear o sistema...
Após um tempo, ao olhar o diretório /opt um arquivo chamado autologin.conf.orig chama atenção...

![Image](https://i.imgur.com/XlcFOEG.png)

Dentro desse arquivo podemos perceber que ele tem um arquivo chamado passwd na pasta /etc/autologin, então vamos até ele

![Image](https://i.imgur.com/Jy72UQn.png)

Com isso conseguimos outra senha... vamos testa-la
Tentei com o usuário chronos mas sem sucesso, já com o user katie... :D

![Image](https://i.imgur.com/RjHHBDQ.png)

Agora que temos nossa primeira flag, vamos para a escalação de privilégios

![Image](https://i.imgur.com/PCFK9AS.png)

Conseguimos executar o /sbin/initctl como root
![Image](https://i.imgur.com/InVFrcN.png)

Podemos olhar os scripts que já estão feitos para tentar reusar algum deles

![Image](https://i.imgur.com/gIWmVAw.png)

Dentro da pasta dos scripts, temos permissão de escrita em alguns arquivos:
![Image](https://i.imgur.com/FO47HW1.png)

Vamos analisar o conteúdo do arquivo test.conf e procurar onde podemos usa-lo para escalar privilégios.

![Image](https://i.imgur.com/nslaa1R.png)

Podemos ver que ele executa um NodeJS, então, vamos criar um payload para Node, no meu caso usei a [reverse shell node do Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#nodejs)
Escrevemos ela no diretório /tmp com o nome de chu.js ( /tmp/chu.js )

![Image](https://i.imgur.com/XBa5q0e.png)

Agora, vamos voltar ao nosso initctl e tentar executar o script test.conf

![Image](https://i.imgur.com/tiQYg4m.png)

Abrimos nossa porta pré-definida em nossa máquina e aguardamos a conexão:
![Image](https://i.imgur.com/seIe9JN.png)

we are r00t

if i helped you, add + respect at my profile :D
<html>
 <body>
  <script src="https://www.hackthebox.eu/badge/148108"></script>
 </body>
 </html>


My references:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
https://linux.die.net/man/8/initctl
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#nodejs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
