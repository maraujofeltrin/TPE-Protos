#ifndef METP_H_
#define METP_H_

#include "selector.h"

/**
 * Estructura para mantener el estado de una conexión METP
 */
struct metp_connection {
    int client_fd;
    enum metp_state {
        METP_AUTH,
        METP_COMMAND,
        METP_RESPONSE,
        METP_DONE,
        METP_ERROR
    } state;
    void *data;
};

/**
 * Comandos METP
 */
enum metp_command {
    METP_GET_STATS = 0x01,
    METP_GET_USERS = 0x02,
    METP_ADD_USER = 0x03,
    METP_DEL_USER = 0x04,
    METP_GET_CONFIG = 0x05,
    METP_SET_CONFIG = 0x06
};

/**
 * Handler para nuevas conexiones METP
 */
extern const struct fd_handler metp_passive_handler;

/**
 * Handler para conexiones METP establecidas
 */
extern const struct fd_handler metp_active_handler;

/**
 * Funciones del handler METP
 */
void metp_passive_accept(struct selector_key *key);
void metp_read(struct selector_key *key);
void metp_write(struct selector_key *key);
void metp_block(struct selector_key *key);
void metp_close(struct selector_key *key);

/**
 * Funciones auxiliares METP
 */
struct metp_connection* metp_connection_new(int client_fd);
void metp_connection_destroy(struct metp_connection *conn);

#endif