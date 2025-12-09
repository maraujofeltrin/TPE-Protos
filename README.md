# TPE-Protos — SOCKS5 Proxy + Management Client

Proyecto que implementa:
- Un servidor SOCKS5 (`socks5d`) con soporte de autenticación y resolución DNS por el proxy.
- Un cliente de management (`socks5_client`) para administrar usuarios, métricas, logs y configuración.

## Requisitos
- Linux, `bash`
- `make`, `gcc`

## Compilación

```bash
make            # compila todo: server, client, utils y tests
make server     # compila solo el servidor
make client     # compila solo el cliente
make clean      # limpia binarios y objetos
```

Artefactos generados:
- Servidor: `build/bin/socks5d`
- Cliente: `build/bin/socks5_client`

## Ejecución — Servidor SOCKS5 (`socks5d`)

Parámetros principales (desde `src/utils/args.c`):
- `-l <SOCKS addr>`: dirección de escucha del proxy (por defecto `0.0.0.0`).
- `-p <SOCKS port>`: puerto de SOCKS (por defecto `1080`).
- `-L <conf addr>`: dirección del servicio de management (por defecto `127.0.0.1`).
- `-P <conf port>`: puerto de management (por defecto `8080`).
- `-u <name>:<pass>`: agrega usuario habilitado para usar el proxy (hasta 10).

Ejemplos:
```bash
# Arrancar con defaults (SOCKS en 0.0.0.0:1080, MGMT en 127.0.0.1:8080)
./build/bin/socks5d

# Escuchar SOCKS en 127.0.0.1:1080 y agregar un usuario
./build/bin/socks5d -l 127.0.0.1 -p 1080 -u user123:pass123

# Cambiar puertos y múltiples usuarios
./build/bin/socks5d -p 1080 -P 9090 -u alice:alicepwd -u bob:bobpwd
```

- Al iniciar el servidor cuando se cree el primer usuario, se le va a adjudicar el rol de ADMIN por default.


## Uso como proxy con `curl`

Una vez que el servidor esté en ejecución, podés verificar que funcione haciendo una solicitud a través del proxy:
```bash
# Conectar vía IPv6 sin autenticación (si el servidor no requiere auth)
curl --proxy socks5h://[::1]:1080 https://www.google.com

# Conectar vía IPv4 sin autenticación
curl --proxy socks5h://127.0.0.1:1080 https://www.google.com

# Modo verbose para ver detalles de la conexión
curl -v --socks5 127.0.0.1:1080 http://www.google.com
 
# Conectar con autenticación usuario:contraseña
curl -x socks5h://admin:pass123@127.0.0.1:1080 http://www.google.com

#Conectarse al servidor si es que este se encuentra corriendo en pampero
curl -x socks5h://admin:pass123@pampero.itba.edu.ar:1080 http://www.google.com/
```

## Ejecución — Cliente de Management (`socks5_client`) 

Autenticación al servicio de management (por defecto usuario administrador precargado `admin:pass123`):

```bash
./build/bin/socks5_client -u admin:pass123 [opciones]
```

### Comandos disponibles (cliente de administración)

El cliente CLI ubicado en `src/client/cmd_line.c` permite interactuar con el servicio de management del servidor SOCKS5.

Los únicos comandos que pueden ejecutar usuarios con rol **user** (y también **admin**) son: `-h`, `-v`, `-m`.  
Todos los demás requieren rol **admin**.

| Opción | Descripción | Permisos |
|--------|-------------|----------|
| `-h` | Muestra la ayuda y finaliza. | - |
| `-v` | Muestra la versión y finaliza. | - |
| `-m` | Obtiene métricas del servidor. | user / admin |
| `-u <user>:<pass>` | Establece credenciales para la sesión de administración. | admin |
| `-p <port>` | Puerto del servicio de management (por defecto: `8080`). | admin |
| `-l` | Obtiene los logs del servidor. | admin |
| `-U` | Lista los usuarios registrados. | admin |
| `-a <username>:<password>` | Agrega un usuario con rol `user`. | admin |
| `-r <username>:<role>` | Modifica el rol de un usuario. | admin |
| `-b <buffer_size>` | Cambia el tamaño del buffer del servidor. | admin |
| `-d <username>` | Elimina un usuario. | admin |


Nota:
- El servidor solo acepta tamaños de buffer entre 1 y 4096.

Ejemplos:
```bash
# Obtener métricas
./build/bin/socks5_client -u admin:pass123 -m

# Listar usuarios
./build/bin/socks5_client -u admin:pass123 -U

# Agregar usuario
./build/bin/socks5_client -u admin:pass123 -a user123:pass123

# Cambiar rol
./build/bin/socks5_client -u admin:pass123 -r user123:admin

# Cambiar tamaño de buffer
./build/bin/socks5_client -u admin:pass123 -b 256

# Eliminar usuario
./build/bin/socks5_client -u admin:pass123 -d user123
```

## Notas de métricas y bytes transferidos
- Para comparaciones, usar deltas de `-m` antes y después de una única petición.

## Estructura del proyecto
- Código fuente: `src/`
- Binarios: `build/bin/`
- Objetos: `build/obj/`
- Tests: `tests/`

