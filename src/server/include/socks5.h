#ifndef SOCKS5_H_
#define SOCKS5_H_

#include "selector.h"

/**
 * Estructura para mantener el estado de una conexión SOCKS5
 */
struct socks5_connection {
    int client_fd;
    int target_fd;
    enum socks5_state {
        SOCKS5_HELLO,
        SOCKS5_REQUEST,
        SOCKS5_CONNECTING,
        SOCKS5_COPY,
        SOCKS5_DONE,
        SOCKS5_ERROR
    } state;
    void *data;
};

/**
 * Handler para nuevas conexiones SOCKS5
 */
extern const struct fd_handler socks5_passive_handler;

/**
 * Handler para conexiones SOCKS5 establecidas
 */
extern const struct fd_handler socks5_active_handler;

/**
 * Funciones del handler SOCKS5
 */
void socks5_passive_accept(struct selector_key *key);
void socks5_read(struct selector_key *key);
void socks5_write(struct selector_key *key);
void socks5_block(struct selector_key *key);
void socks5_close(struct selector_key *key);

/**
 * Funciones auxiliares SOCKS5
 */
struct socks5_connection* socks5_connection_new(int client_fd);
void socks5_connection_destroy(struct socks5_connection *conn);

#endif