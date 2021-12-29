<html>
 <body>
  <script src="https://www.hackthebox.eu/badge/148108"></script>
 </body>
 </html>


Back to all write-ups: [here](https://repo4chu.github.io/hackthebox/)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Forge - HackTheBox
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
![Image](https://i.imgur.com/uxucbR3.png)

WriteUp by [chu](https://app.hackthebox.eu/profile/148108/)

Machine Maker: [NoobHacker9999](https://www.hackthebox.eu/home/users/profile/393721)

**Tools** utilizadas:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
nmap
BurpSuite
netcat
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Usaremos o nmap para encontrar portas e serviços rodando na máquina:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
nmap -sS -Pn -A 10.10.11.111 -p 22,80

-v: verbose(output mais detalhado).
-sS: syn scan.
-Pn: já sabemos que o host está ativo então desativamos o discovery.
-A: Detecção de OS, detecção de versão, script scanning, and traceroute
-p: especifica as portas
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Nosso resultado:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4f:78:65:66:29:e4:87:6b:3c:cc:b4:3a:d2:57:20:ac (RSA)
|   256 79:df:3a:f1:fe:87:4a:57:b0:fd:4e:d0:54:c6:28:d9 (ECDSA)
|_  256 b0:58:11:40:6d:8c:bd:c5:72:aa:83:08:c5:51:fb:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Gallery
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: 10.10.11.111; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   207.80 ms 10.10.14.1
2   207.98 ms forge.htb (10.10.11.111)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Podemos ver duas portas abertas, a 22(SSH) e a 80(HTTP).

Ao acessar o site pelo IP, somos redirecionados para o nome forge.htb, portanto, precisamos adicionar o nome forge.htb ao arquivo /etc/hosts

![Image](https://i.imgur.com/dPg1ZuS.png)


Agora que conseguimos acessar o site, podemos ver um link para uma página de upload.

![Image](https://i.imgur.com/AhOgfBm.png)

Ao acessar, temos duas opções de upload. Podemos fazer uploads de arquivos localmente ou via URL. Fiz diversos testes através do upload local mas não obtive sucesso.
![Image](https://i.imgur.com/TNrrX9G.png)

Ao tentar passar um endereço local pela URL, pude perceber que havia uma blacklist ativa.
![Image](https://i.imgur.com/Kf2xuEE.png)

Um bypass simples foi utilizar caracteres maiusculos, isso fez com que eu fosse capaz de passar pela blacklist.

![Image](https://i.imgur.com/8vHOo8n.png)

Com isso, recebemos o link do upload bem sucedido.
![Image](https://i.imgur.com/e17q2ik.png)

Usando o 'curl' podemos ver o conteudo do arquivo com a index.html, o que significa que nossa falha de SSRF foi validada.
![Image](https://i.imgur.com/cN0y3sm.png)

Usando o ffuf para enumerar subdominios, temos um resultado interessante: admin.forge.htb
![Image](https://i.imgur.com/o0XkqUU.png)

Adicionamos o novo nome ao arquivo /etc/hosts.
![Image](https://i.imgur.com/scTg9ay.png)

Acessando a página http://admin.forge.htb, recebemos a mensagem de que só é possível o acesso local.
![Image](https://i.imgur.com/az7HTPY.png)

Vamos utilizar a tecnica já validada de SSRF na página http://forge.htb/upload para receber o conteúdo da página http://admin.forge.htb 
![Image](https://i.imgur.com/Br3eofl.png)

Podemos perceber que o nome http://admin.forge.htb esta sendo bloqueado do mesmo modo da tentativa feita realizada utilizando http://localhost
![Image](https://i.imgur.com/U63kc2q.png)

Vamos utilizar a mesma técnica de caracteres maiúsculos para conseguir um bypass para a página do admin.

![Image](https://i.imgur.com/v8AVy1Z.png)

Utilizei o BurpSuite para facilitar a visualização da resposta.
Com isso, conseguimos ler o conteúdo da página http://admin.forge.htb validando o bypass via SSRF.
Podemos ver duas páginas além da index.html 
/annoucements
/upload
![Image](https://i.imgur.com/DbgET3k.png)

Agora vamos passar o caminho completo para a página que queremos, http://admin.forge.HTB/annoucements
![Image](https://i.imgur.com/AVukEsk.png)

Na resposta da nossa request, conseguimos ler o conteúdo da página http://admin.forge.htb/annoucements e nela é possível obter credenciais de um serviço FTP interno.
Além disso, também podemos ver uma mensagem dizendo que a página de upload agora suporta outros protocolos, como FTP e FTPS.
Na terceira mensagem, temos o anuncio que diz como utilizar os parametros.
![Image](https://i.imgur.com/7QHd3GX.png)


Temos um servidor FTP rodando internamente, e podemos interagir com ele através da página http://admin.forge.htb/upload usando o protocolo FTP, podemos usar os parâmetros descritos no terceiro ponto.
Como o endereço admin.forge.htb e localhost estão na blacklist, precisamos utilizar o bypass de caracteres maiusculos em ambos.
Nossa query final http://admin.forge.HTB/upload?u=ftp://user:heightofsecurity123!@LoCaLhOsT
![Image](https://i.imgur.com/xGQ5AEt.png)


Com isso, temos a resposta de nossa request a listagem do diretório FTP, no caso /home/user
![Image](https://i.imgur.com/ZhcDSev.png)



Conseguimos obter o link para nossa primeira flag pasasndo o caminho completo do arquivo: http://admin.forge.HTB/upload?u=ftp://user:heightofsecurity123!@LoCaLhOsT/user.txt
![Image](https://i.imgur.com/kWC9bX4.png)

Com isso, recebemos nossa primeira flag
![Image](https://i.imgur.com/9zcoRi0.png)

Tentei realizar o acesso via SSH utilizando as credenciais do servidor FTP, porém, o método de autenticação é através de chave pública.
![Image](https://i.imgur.com/wEXxVoP.png)

Então vamos ler a chave RSA no diretório SSH do usuário.
http://admin.forge.HTB/upload?u=ftp://user:heightofsecurity123!@LoCaLhOsT/.ssh/id_rsa
![Image](https://i.imgur.com/fZ7sbPU.png)

Com isso temos a chave RSA privada do usuário.
![Image](https://i.imgur.com/emiskYu.png)


we are in


if i helped you, add + respect at my [profile](https://app.hackthebox.eu/profile/148108) :D
<html>
 <body>
  <script src="https://www.hackthebox.eu/badge/148108"></script>
 </body>
 </html>


My references:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
