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










if i helped you, add + respect at my [profile](https://app.hackthebox.eu/profile/148108) :D
<html>
 <body>
  <script src="https://www.hackthebox.eu/badge/148108"></script>
 </body>
 </html>


My references:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
