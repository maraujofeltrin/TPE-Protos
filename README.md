# TPE-Protos — SOCKS5 Proxy + Management Client

Proyecto que implementa:
- Un servidor SOCKS5 (`socks5d`) con soporte de autenticación y resolución DNS por el proxy.
- Un cliente de management (`socks5_client`) para administrar usuarios, métricas, logs y configuración.

## Requisitos
- Linux, `bash`
- `make`, `gcc`

## Compilación

```bash
make            # compila todo: server y client
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
- `-N`: deshabilita disectors.

Ejemplos:
```bash
# Arrancar con defaults (SOCKS en 0.0.0.0:1080, MGMT en 127.0.0.1:8080)
./build/bin/socks5d

# Escuchar SOCKS en 127.0.0.1:1080 y agregar un usuario
./build/bin/socks5d -l 127.0.0.1 -p 1080 -u user123:pass123

# Cambiar puertos y múltiples usuarios
./build/bin/socks5d -p 1080 -P 9090 -u alice:alicepwd -u bob:bobpwd
```

## Uso como proxy con `curl`

Preferir `socks5h` para que el DNS lo resuelva el servidor (hostname por proxy):
```bash
# Sin autenticación
curl --proxy socks5h://127.0.0.1:1080 https://example.com
```

## Ejecución — Cliente de Management (`socks5_client`)

Autenticación al servicio de management (por defecto usuario administrador precargado `admin:password123`):

```bash
./build/bin/socks5_client -u admin:password123 [opciones]
```

Comandos disponibles (`src/client/cmd_line.c`):
- `-h`: ayuda y salir.
- `-v`: versión y salir.
- `-p <port>`: puerto del servicio de management (por defecto `8080`).
- `-u <user>:<pass>`: credenciales de management.
- `-l`: GET_LOGS — obtener logs.
- `-m`: GET_METRICS — obtener métricas.
- `-U`: USERS — listar usuarios.
- `-a <username>:<password>`: ADD_USER — agregar usuario (rol `user`).
- `-r <username>:<role>`: ROLE_SETTER — setear rol (`admin` | `user`).
- `-b <buffer_size>`: BUFFER_NEWSIZE — setear tamaño de buffer (bytes).
- `-d <username>`: DELETE_USER — eliminar usuario.
- `-q`: QUIT — salir.

Ejemplos:
```bash
# Obtener métricas
./build/bin/socks5_client -u admin:password123 -m

# Listar usuarios
./build/bin/socks5_client -u admin:password123 -U

# Agregar usuario
./build/bin/socks5_client -u admin:password123 -a user123:pass123

# Cambiar rol
./build/bin/socks5_client -u admin:password123 -r user123:admin

# Cambiar tamaño de buffer
./build/bin/socks5_client -u admin:password123 -b 65536

# Eliminar usuario
./build/bin/socks5_client -u admin:password123 -d user123
```

## Notas de métricas y bytes transferidos
- Para comparaciones, usar deltas de `GET_METRICS` antes y después de una única petición.

## Estructura del proyecto
- Código fuente: `src/`
- Binarios: `build/bin/`
- Objetos: `build/obj/`
- Tests: `tests/`

