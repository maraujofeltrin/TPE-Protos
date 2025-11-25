#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
/*

#include "include/server.h"
#include "include/socks5.h"
#include "include/metp.h"

// Variables globales del servidor
bool done = false;
static fd_selector main_selector = NULL;
static int socks5_server_fd = -1;
static int metp_server_fd = -1;

void 
sigterm_handler(const int signal) {
    printf("\nSignal %d received, shutting down server...\n", signal);
    done = true;
}

int 
setup_passive_socket(const char* addr, const unsigned short port) {
    int server_fd;
    struct sockaddr_in server_addr;
    
    // Crear socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("Error al crear socket");
        return -1;
    }
    
    // Configurar reutilización de dirección
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Error en setsockopt");
        close(server_fd);
        return -1;
    }
    
    // Configurar dirección del servidor
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (addr == NULL || strcmp(addr, "0.0.0.0") == 0) {
        server_addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        if (inet_pton(AF_INET, addr, &server_addr.sin_addr) <= 0) {
            fprintf(stderr, "Dirección IP inválida: %s\n", addr);
            close(server_fd);
            return -1;
        }
    }
    
    // Bind
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error en bind");
        close(server_fd);
        return -1;
    }
    
    // Listen
    if (listen(server_fd, BACKLOG) < 0) {
        perror("Error en listen");
        close(server_fd);
        return -1;
    }
    
    // Configurar socket no bloqueante
    if (selector_fd_set_nio(server_fd) == -1) {
        perror("Error configurando socket no bloqueante");
        close(server_fd);
        return -1;
    }
    
    return server_fd;
}

int 
server_init(const struct socks5args *args) {
    int ret = 0;
    
    // Configurar manejadores de señales
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);
    
    // Inicializar selector
    const struct selector_init conf = {
        .signal = SIGUSR1,
        .select_timeout = {
            .tv_sec  = 10,
            .tv_nsec = 0,
        },
    };
    
    if (0 != selector_init(&conf)) {
        fprintf(stderr, "Error inicializando selector\n");
        return 1;
    }
    
    main_selector = selector_new(1024);
    if (main_selector == NULL) {
        fprintf(stderr, "Error creando selector\n");
        ret = 1;
        goto finally;
    }
    
    // Configurar socket del servidor SOCKS5
    socks5_server_fd = setup_passive_socket(args->socks_addr, args->socks_port);
    if (socks5_server_fd < 0) {
        fprintf(stderr, "Error configurando socket SOCKS5\n");
        ret = 1;
        goto finally;
    }
    
    if (SELECTOR_SUCCESS != selector_register(main_selector, socks5_server_fd, 
                                            &socks5_passive_handler, OP_READ, NULL)) {
        fprintf(stderr, "Error registrando fd del servidor SOCKS5\n");
        ret = 1;
        goto finally;
    }
    
    printf("SOCKS5 server listening on %s:%d\n", 
           args->socks_addr ? args->socks_addr : "0.0.0.0", 
           args->socks_port);
    
    // Configurar socket de administración METP
    metp_server_fd = setup_passive_socket(args->mng_addr, args->mng_port);
    if (metp_server_fd < 0) {
        fprintf(stderr, "Error configurando socket METP\n");
        ret = 1;
        goto finally;
    }
    
    if (SELECTOR_SUCCESS != selector_register(main_selector, metp_server_fd, 
                                            &metp_passive_handler, OP_READ, NULL)) {
        fprintf(stderr, "Error registrando fd del servidor METP\n");
        ret = 1;
        goto finally;
    }
    
    printf("METP server listening on %s:%d\n", 
           args->mng_addr ? args->mng_addr : "127.0.0.1", 
           args->mng_port);
    
    printf("Server started successfully. Press Ctrl+C to stop.\n");
    
finally:
    if (ret != 0) {
        server_cleanup();
    }
    return ret;
}

int 
server_run(void) {
    int ret = 0;
    
    // Loop principal del servidor
    while (!done) {
        selector_status ss = selector_select(main_selector);
        if (ss != SELECTOR_SUCCESS) {
            if (ss == SELECTOR_IO && (errno == EINTR || errno == EAGAIN)) {
                // Interrumpido por señal, continuar
                continue;
            }
            fprintf(stderr, "Error en selector: %s\n", selector_error(ss));
            ret = 1;
            break;
        }
    }
    
    printf("\nShutting down server...\n");
    return ret;
}

void 
server_cleanup(void) {
    if (socks5_server_fd >= 0) {
        close(socks5_server_fd);
        socks5_server_fd = -1;
    }
    if (metp_server_fd >= 0) {
        close(metp_server_fd);
        metp_server_fd = -1;
    }
    if (main_selector != NULL) {
        selector_destroy(main_selector);
        main_selector = NULL;
    }
    selector_close();
}

int 
main(const int argc, char **argv) {
    // Parsear argumentos de línea de comandos
    struct socks5args args;
    parse_args(argc, argv, &args);
    
    // Inicializar servidor
    if (server_init(&args) != 0) {
        return 1;
    }
    
    // Ejecutar servidor
    int ret = server_run();
    
    // Limpiar recursos
    server_cleanup();
    
    return ret;
}

void 
socks5_close(struct selector_key *key) {
    struct socks5_connection *conn = (struct socks5_connection *)key->data;
    
    printf("Closing SOCKS5 connection fd=%d\n", key->fd);
    
    if (conn != NULL) {
        socks5_connection_destroy(conn);
    }
}

void 
socks5_read(struct selector_key *key) {
    struct socks5_connection *conn = (struct socks5_connection *)key->data;
    
    printf("SOCKS5 read on fd=%d, state=%d\n", key->fd, conn->state);
    
    // TODO: Implementar lógica de lectura según el estado
    switch (conn->state) {
        case SOCKS5_HELLO:
            // Leer saludo inicial del cliente
            break;
        case SOCKS5_REQUEST:
            // Leer petición de conexión
            break;
        case SOCKS5_COPY:
            // Copiar datos entre cliente y target
            break;
        default:
            printf("Estado SOCKS5 no manejado: %d\n", conn->state);
            break;
    }
}

void 
socks5_write(struct selector_key *key) {
    struct socks5_connection *conn = (struct socks5_connection *)key->data;
    
    printf("SOCKS5 write on fd=%d, state=%d\n", key->fd, conn->state);
    
    // TODO: Implementar lógica de escritura según el estado
    switch (conn->state) {
        case SOCKS5_HELLO:
            // Enviar respuesta al saludo
            break;
        case SOCKS5_REQUEST:
            // Enviar respuesta a la petición
            break;
        case SOCKS5_COPY:
            // Copiar datos entre cliente y target
            break;
        default:
            printf("Unhandled SOCKS5 state: %d\n", conn->state);
            break;
    }
}

void 
socks5_block(struct selector_key *key) {
    struct socks5_connection *conn = (struct socks5_connection *)key->data;
    
    printf("SOCKS5 block on fd=%d, state=%d\n", key->fd, conn->state);
    
    // TODO: Manejar operaciones bloqueantes (ej: resolución DNS)
}


void 
metp_read(struct selector_key *key) {
    struct metp_connection *conn = (struct metp_connection *)key->data;
    
    printf("METP read on fd=%d, state=%d\n", key->fd, conn->state);
    
    // TODO: Implementar lógica de lectura según el estado
    switch (conn->state) {
        case METP_AUTH:
            // Leer credenciales de autenticación
            break;
        case METP_COMMAND:
            // Leer comando de administración
            break;
        default:
            printf("Unhandled METP state: %d\n", conn->state);
            break;
    }
}

void 
metp_write(struct selector_key *key) {
    struct metp_connection *conn = (struct metp_connection *)key->data;
    
    printf("METP write on fd=%d, state=%d\n", key->fd, conn->state);
    
    // TODO: Implementar lógica de escritura según el estado
    switch (conn->state) {
        case METP_AUTH:
            // Enviar respuesta de autenticación
            break;
        case METP_RESPONSE:
            // Enviar respuesta al comando
            break;
        default:
            printf("Unhandled METP state: %d\n", conn->state);
            break;
    }
}

void 
metp_block(struct selector_key *key) {
    struct metp_connection *conn = (struct metp_connection *)key->data;
    
    printf("METP block on fd=%d, state=%d\n", key->fd, conn->state);
    
    // TODO: Manejar operaciones bloqueantes (ej: consultas a base de datos)
}

*/