#ifndef SERVER_H_
#define SERVER_H_

#include <stdbool.h>
#include "args.h"
#include "selector.h"

#define BACKLOG 20

/**
 * Variable global para controlar el estado del servidor
 */
extern bool done;

/**
 * Configurar y inicializar el servidor
 */
int server_init(const struct socks5args *args);

/**
 * Ejecutar el loop principal del servidor
 */
int server_run(void);

/**
 * Limpiar recursos del servidor
 */
void server_cleanup(void);

/**
 * Configurar un socket pasivo (servidor)
 */
int setup_passive_socket(const char* addr, const unsigned short port);

/**
 * Manejador de señales para terminar el servidor
 */
void sigterm_handler(const int signal);

#endif