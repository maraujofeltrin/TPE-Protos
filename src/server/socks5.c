#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "include/socks5.h"
#include "selector.h"

// Definición de los handlers SOCKS5
const struct fd_handler socks5_passive_handler = {
    .handle_read   = socks5_passive_accept,
    .handle_write  = NULL,
    .handle_close  = NULL,
};

const struct fd_handler socks5_active_handler = {
    .handle_read   = socks5_read,
    .handle_write  = socks5_write,
    .handle_block  = socks5_block,
    .handle_close  = socks5_close,
};

void 
socks5_passive_accept(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    
    int client_fd = accept(key->fd, (struct sockaddr*)&client_addr, &client_addr_len);
    if (client_fd == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("Error al aceptar conexión SOCKS5");
        }
        return;
    }
    
    printf("New SOCKS5 connection from client fd=%d\n", client_fd);
    
    // Crear nueva conexión SOCKS5
    struct socks5_connection *conn = socks5_connection_new(client_fd);
    if (conn == NULL) {
        close(client_fd);
        return;
    }
    
    // Configurar socket no bloqueante
    if (selector_fd_set_nio(client_fd) == -1) {
        perror("Error configurando socket no bloqueante");
        socks5_connection_destroy(conn);
        close(client_fd);
        return;
    }
    
    // Registrar en el selector
    if (SELECTOR_SUCCESS != selector_register(key->s, client_fd, &socks5_active_handler, 
                                            OP_READ, conn)) {
        fprintf(stderr, "Error registrando conexión SOCKS5\n");
        socks5_connection_destroy(conn);
        close(client_fd);
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
socks5_close(struct selector_key *key) {
    struct socks5_connection *conn = (struct socks5_connection *)key->data;
    
    printf("Closing SOCKS5 connection fd=%d\n", key->fd);
    
    if (conn != NULL) {
        socks5_connection_destroy(conn);
    }
}

struct socks5_connection* 
socks5_connection_new(int client_fd) {
    struct socks5_connection *conn = malloc(sizeof(*conn));
    if (conn == NULL) {
        return NULL;
    }
    
    conn->client_fd = client_fd;
    conn->target_fd = -1;
    conn->state = SOCKS5_HELLO;
    conn->data = NULL;
    
    return conn;
}

void 
socks5_connection_destroy(struct socks5_connection *conn) {
    if (conn == NULL) {
        return;
    }
    
    if (conn->target_fd >= 0) {
        close(conn->target_fd);
    }
    
    if (conn->data != NULL) {
        free(conn->data);
    }
    
    free(conn);
}