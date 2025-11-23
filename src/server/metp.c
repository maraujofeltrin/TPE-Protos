#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "include/metp.h"
#include "selector.h"

// Definición de los handlers METP
const struct fd_handler metp_passive_handler = {
    .handle_read   = metp_passive_accept,
    .handle_write  = NULL,
    .handle_close  = NULL,
};

const struct fd_handler metp_active_handler = {
    .handle_read   = metp_read,
    .handle_write  = metp_write,
    .handle_block  = metp_block,
    .handle_close  = metp_close,
};

void 
metp_passive_accept(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    
    int client_fd = accept(key->fd, (struct sockaddr*)&client_addr, &client_addr_len);
    if (client_fd == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("Error al aceptar conexión METP");
        }
        return;
    }
    
    printf("New METP connection from client fd=%d\n", client_fd);
    
    // Crear nueva conexión METP
    struct metp_connection *conn = metp_connection_new(client_fd);
    if (conn == NULL) {
        close(client_fd);
        return;
    }
    
    // Configurar socket no bloqueante
    if (selector_fd_set_nio(client_fd) == -1) {
        perror("Error configurando socket no bloqueante");
        metp_connection_destroy(conn);
        close(client_fd);
        return;
    }
    
    // Registrar en el selector
    if (SELECTOR_SUCCESS != selector_register(key->s, client_fd, &metp_active_handler, 
                                            OP_READ, conn)) {
        fprintf(stderr, "Error registrando conexión METP\n");
        metp_connection_destroy(conn);
        close(client_fd);
    }
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

void 
metp_close(struct selector_key *key) {
    struct metp_connection *conn = (struct metp_connection *)key->data;
    
    printf("Closing METP connection fd=%d\n", key->fd);
    
    if (conn != NULL) {
        metp_connection_destroy(conn);
    }
}

struct metp_connection* 
metp_connection_new(int client_fd) {
    struct metp_connection *conn = malloc(sizeof(*conn));
    if (conn == NULL) {
        return NULL;
    }
    
    conn->client_fd = client_fd;
    conn->state = METP_AUTH;
    conn->data = NULL;
    
    return conn;
}

void 
metp_connection_destroy(struct metp_connection *conn) {
    if (conn == NULL) {
        return;
    }
    
    if (conn->data != NULL) {
        free(conn->data);
    }
    
    free(conn);
}