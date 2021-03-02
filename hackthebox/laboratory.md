<html>
 <body>
  <script src="https://www.hackthebox.eu/badge/148108"></script>
 </body>
 </html>


Back to all write-ups: [here](https://repo4chu.github.io/hackthebox/)


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Laboratory - HackTheBox - WriteUp
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
![image](https://i.imgur.com/Yy18N58.png)

**Tools** utilizadas:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
nmap
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 25:ba:64:8f:79:9d:5d:95:97:2c:1b:b2:5e:9b:55:0d (RSA)
|   256 28:00:89:05:55:f9:a2:ea:3c:7d:70:ea:4d:ea:60:0f (ECDSA)
|_  256 77:20:ff:e9:46:c0:68:92:1a:0b:21:29:d1:53:aa:87 (ED25519)
80/tcp  open  http     Apache httpd 2.4.41
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to https://laboratory.htb/
443/tcp open  ssl/http Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: The Laboratory
| ssl-cert: Subject: commonName=laboratory.htb
| Subject Alternative Name: DNS:git.laboratory.htb
| Issuer: commonName=laboratory.htb
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-07-05T10:39:28
| Not valid after:  2024-03-03T10:39:28
| MD5:   2873 91a5 5022 f323 4b95 df98 b61a eb6c
|_SHA-1: 0875 3a7e eef6 8f50 0349 510d 9fbf abc3 c70a a1ca
| tls-alpn: 
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Podemos perceber dois sites:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
https://laboratory.htb/
https://git.laboratory.htb/
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Ao acessar o site https://git.laboratory.htb/ nos deparamos com um [GitLab](https://about.gitlab.com/).

Em seguida, vamos tentar nos cadastrar:
![Image](https://i.imgur.com/ZBrnqIP.png)

Após o cadastro ser bem sucedido, temos acesso ao painel do GitLab, portanto, vamos tententar identificar a versão utilizada.

Na página https://git.laboratory.htb/help podemos identificar a versão exata que está sendo utilizada:
![Image](https://i.imgur.com/Jf44fiC.png)


Após encontrar a versão, podemos fazer buscas por exploits e falhas já conhecidas da versão...

Um [report](https://hackerone.com/reports/827052) do site de bugbounty HackerOne é nosso ponto inicial.

Portanto, devemos primeiramente criar dois projetos:

Vou chamar um de 'chu' e outro de 'stevenseagal' (XD)

Projeto 1 - chu:
![Image](https://i.imgur.com/xX8oTlp.png)

Projeto 2 - stevenseagal: 
![Image](https://i.imgur.com/EtNLpZ9.png)

Podemos conferir os dois projetos criados:
![Image](https://i.imgur.com/ntSr8u1.png)

Depois de criarmos os dois projetos, vamos tentar simular o que foi feito no report do H1.

Primeiro passo criar um novo Issue no projeto 'chu'
![Image](https://i.imgur.com/xMcW43V.png)

Dentro do issue iremos usar o mesmo payload do report
![Image](https://i.imgur.com/xMcW43V.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
![a](/uploads/11111111111111111111111111111111/../../../../../../../../../../../../../../etc/passwd)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Logo em seguida, vamos mover o Issue para o outro projeto. (em meu caso do projeto chu para stevenseagal)
![Image]https://i.imgur.com/9r5mEnz.png

Ao mover, dentro do projeto 2(stevenseagal) podemos perceber que ele já renomeou o arquivo em anexo chamado 'a' para o arquivo que queriamos (/etc/passwd)
![Image](https://i.imgur.com/OND9zlB.png)

