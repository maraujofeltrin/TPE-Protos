#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "selector.h"
#include "../include/metp.h"
#include "../include/users.h"

#define BUFFER_MAX 1024

static unsigned send_response(struct selector_key *key, const char *message, unsigned next_state);
static void write_message_to_buffer(buffer *, const char *message);
static unsigned metp_handshake_read(struct selector_key * key);
static unsigned metp_handshake_response_write(struct selector_key * key);
static unsigned metp_write_auth(struct selector_key * key);
static unsigned metp_read_auth(struct selector_key * key);
static unsigned metp_request_read(struct selector_key * key);
static void metp_request_arrival(const unsigned state, struct selector_key * key);
static unsigned metp_request_response_write(struct selector_key * key);
static void metp_error_arrival(const unsigned state, struct selector_key * key);
static unsigned metp_error_write(struct selector_key * key);
static void metp_200(struct selector_key * key);


static const struct state_definition metp_states_def[] = {
    [METP_HANDSHAKE] = {
        .state = METP_HANDSHAKE,
        .on_read_ready = metp_handshake_read,
    },
    [METP_HANDSHAKE_RESPONSE] = {
        .state = METP_HANDSHAKE_RESPONSE,
        .on_write_ready = metp_handshake_response_write,
    },
    [METP_AUTH] = {
        .state = METP_AUTH,
        .on_read_ready = metp_read_auth,
    },
    [METP_AUTH_RESPONSE] = {
        .state = METP_AUTH_RESPONSE,
        .on_write_ready = metp_write_auth,
    },
    [METP_REQUEST] = {
        .state = METP_REQUEST,
        .on_arrival = metp_request_arrival,
        .on_read_ready = metp_request_read,
    },
    [METP_REQUEST_RESPONSE] = {
        .state = METP_REQUEST_RESPONSE,
        .on_write_ready = metp_request_response_write, 
    },
    [METP_TERMINATED] = {
        .state = METP_TERMINATED,
    },
    [METP_ERROR] = {
        .state = METP_ERROR,
        .on_arrival = metp_error_arrival, 
        .on_write_ready = metp_error_write,
    }
};

// Función auxiliar para escribir mensajes en el buffer de salida
static void write_message_to_buffer(buffer * b, const char *message) {
    if (!b || !message) return;
    
    size_t len = strlen(message);
    for (size_t i = 0; i < len; i++) {
        buffer_write(b, (uint8_t)message[i]);
    }
}

static unsigned send_response(struct selector_key * key, const char * message, unsigned next_state) {
    metp_connection_t *conn = (metp_connection_t *)key->data;
    if (!conn || !conn->buffer_w) return METP_ERROR;
    
    write_message_to_buffer(conn->buffer_w, message);
    selector_set_interest_key(key, OP_WRITE);
    return next_state;
}

const struct state_definition * get_metp_state_definition() {
    return metp_states_def;
}

static unsigned metp_handshake_read(struct selector_key * key) {
    metp_connection_t * connection = key->data;
    size_t cant;    
    unsigned state = METP_HANDSHAKE;
    uint8_t *ptr = buffer_write_ptr(connection->buffer_w, &cant);
    ssize_t n = recv(connection->fd_client, ptr, cant, 0);

    if(n <= 0) {
        perror("metp handshake recv");
        return METP_ERROR;
    }
    buffer_write_adv(connection->buffer_r, (size_t)n);
    
    uint8_t a;
    while(buffer_can_read(connection->buffer_r)) {
        a = buffer_read(connection->buffer_r);
        
        if(connection->parser.auth_parser.cantBytes < BUFFER_MAX - 1) {
            connection->parser.auth_parser.text[connection->parser.auth_parser.cantBytes++] = (char)a;
        }
        else{
            return send_response(key, "400 Bad Request: Line too long\n", METP_ERROR);
        }

        if(a == '\n' || connection->parser.auth_parser.cantBytes == BUFFER_MAX - 1) {
            connection->parser.auth_parser.text[connection->parser.auth_parser.cantBytes] = '\0';
            connection->parser.auth_parser.cantBytes = 0;
            char * resp;
            size_t m, l;
            uint8_t * tor;
            //VER DE MODULARIZAR PARA NO REPETIR
            if(strcmp(connection->parser.auth_parser.text, "HELLO METP/1.0\n") == 0) {
                resp = "200 METP Handshake Successful\n";
                tor = buffer_write_ptr(connection->buffer_w, &m);
                l = strlen(resp);
                if(l > m) {
                    l = m;
                }
                memcpy(tor, resp, l);
                buffer_write_adv(connection->buffer_w, l);
                selector_set_interest_key(key, OP_WRITE);
                state = METP_HANDSHAKE_RESPONSE;
            }
            else {
                resp = "400 Bad Request: Invalid Handshake\n";
                tor = buffer_write_ptr(connection->buffer_w, &m);
                l = strlen(resp);
                if(l > m) {
                    l = m;
                }
                memcpy(tor, resp, l);
                buffer_write_adv(connection->buffer_w, l);
                state = METP_ERROR;
            }
        }
    }
    return state;
}

static unsigned metp_handshake_response_write(struct selector_key * key) {
    metp_connection_t * connection = key->data;
    size_t c;
    uint8_t *src = buffer_read_ptr(connection->buffer_w, &c);
    if(c <= 0){
        return METP_ERROR;
    }
    
    ssize_t s = send(connection->fd_client, src, c, 0);

    if(s <= 0){
        return METP_ERROR;
    }

    buffer_read_adv(connection->buffer_w, (size_t)s);

    if(!buffer_can_read(connection->buffer_w)){
        selector_set_interest_key(key, OP_READ);
        return METP_AUTH;
    }

    return METP_HANDSHAKE_RESPONSE;
}


static void metp_error_arrival(const unsigned state, struct selector_key * key) {
    metp_connection_t * connection = key->data;
    
    if(!buffer_can_read(connection->buffer_w)){
        write_message_to_buffer(connection->buffer_w, "500 Internal Server Error\n");
    }
    selector_set_interest_key(key, OP_WRITE);
}

static unsigned metp_error_write(struct selector_key * key) {
    metp_connection_t * connection = key->data;
    
    size_t bytes;
    uint8_t *src = buffer_read_ptr(connection->buffer_w, &bytes);
    
    if (bytes > 0) {
        ssize_t sent = send(connection->fd_client, src, bytes, MSG_NOSIGNAL);
        if (sent > 0) {
            buffer_read_adv(connection->buffer_w, sent);
        }
    }
    
    // En caso de error, siempre limpiamos y cerramos
    selector_unregister_fd(key->s, connection->fd_client);
    close(connection->fd_client);
    return METP_TERMINATED;
}

static unsigned metp_read_auth(struct selector_key * key) {
    metp_connection_t *conn = (metp_connection_t *)key->data;
    if(!conn || !conn->buffer_r || !conn->buffer_w) return METP_ERROR;

    buffer *rb = conn->buffer_r;
    size_t avail;
    uint8_t *in = buffer_write_ptr(rb, &avail);
    ssize_t n = recv(key->fd, in, avail, 0);
    if (n <= 0) {
        perror("metp recv");
        return METP_ERROR;
    }
    buffer_write_adv(rb, (size_t)n);
    while (buffer_can_read(rb)) {
        uint8_t c = buffer_read(rb);
        size_t idx = conn->parser.auth_parser.cantBytes;
        if (idx >= BUFFER_MAX - 1) {
            return send_response(key, "400 Bad Request: Line too long\n", METP_ERROR);
        }
        conn->parser.auth_parser.text[idx++] = (char)c;
        conn->parser.auth_parser.cantBytes = idx;

        if (c == '\n') {
            conn->parser.auth_parser.text[idx] = '\0';
            conn->parser.auth_parser.cantBytes = 0;

            char *saveptr = NULL;
            char *cmd = strtok_r(conn->parser.auth_parser.text, " \r\n", &saveptr);
            if (cmd == NULL) continue;

            if (strcmp(cmd, "AUTH") == 0) {
                char *user = strtok_r(NULL, " \r\n", &saveptr);
                char *pass = strtok_r(NULL, " \r\n", &saveptr);
                if (user == NULL || pass == NULL) {
                    return send_response(key, "400 Bad Request: Missing user or password\n", METP_ERROR);
                }

                user_t *u = authenticate_user(user, pass);
                if (u) {
                    conn->authenticated = true;
                    strncpy(conn->cur_user, user, USER_MAX - 1);
                    conn->cur_user[USER_MAX - 1] = '\0';
                    write_message_to_buffer(conn->buffer_w, "200 OK\n");
                } else {
                    write_message_to_buffer(conn->buffer_w, "401 Unauthorized. Closing connection.\n");
                    conn->close = true;
                }

                selector_set_interest_key(key, OP_WRITE);
                return METP_AUTH_RESPONSE;
            }

            return send_response(key, "400 Bad Request\n", METP_ERROR);
        }
    }

    return METP_AUTH;
}

static unsigned metp_write_auth(struct selector_key * key) {
    metp_connection_t *conn = (metp_connection_t *)key->data;
    if (!conn || !conn->buffer_w) return METP_ERROR;

    buffer *wb = conn->buffer_w;
    size_t bytes;
    uint8_t *src = buffer_read_ptr(wb, &bytes);
    ssize_t sent = send(key->fd, src, bytes, MSG_NOSIGNAL);
    if (sent <= 0) {
        return METP_ERROR;
    }
    buffer_read_adv(wb, sent);

    if (!buffer_can_read(wb)) {
        if (conn->authenticated) {
            selector_set_interest_key(key, OP_READ);
            return METP_REQUEST;
        } else {
            close(conn->fd_client);
            return METP_TERMINATED;
        }
    }
    return METP_AUTH_RESPONSE;
}

static void metp_request_arrival(const unsigned state, struct selector_key * key) {
    (void)state;
    metp_connection_t *conn = (metp_connection_t *)key->data;
    conn->parser.request_parser.cantBytes = 0;
    conn->parser.request_parser.text[0] = '\0';
    selector_set_interest_key(key, OP_READ);
}

static unsigned metp_request_read(struct selector_key * key) {
    metp_connection_t *conn = (metp_connection_t *)key->data;
    buffer *rb = conn->buffer_r;
    unsigned int state = METP_ERROR;
    size_t avail;
    uint8_t *in = buffer_write_ptr(rb, &avail);
    ssize_t n = recv(key->fd, in, avail, 0);
    if (n < 0) {
        perror("metp recv");
        //VER, IMPRIMIR ERROR
        selector_set_interest_key(key, OP_WRITE);
        return METP_ERROR;
    }
    if(n == 0) {
        conn->close = true;
        selector_set_interest_key(key, OP_WRITE);
        return METP_REQUEST_RESPONSE;
    }
    buffer_write_adv(rb, (size_t)n);
    while (buffer_can_read(rb)) {
        uint8_t c = buffer_read(rb);
        size_t idx = conn->parser.request_parser.cantBytes;
        if (idx >= BUFFER_MAX - 1) {
            send_response(key, "400 Bad Request: Line too long\n",  METP_ERROR);
            selector_set_interest_key(key, OP_WRITE);
            return  METP_REQUEST_RESPONSE;
        }else{
            conn->parser.request_parser.text[idx++] = (char)c;
            conn->parser.request_parser.cantBytes = idx;
        }
        if(c == '\n' || idx == BUFFER_MAX - 1) {
            conn->parser.request_parser.text[idx] = '\0';
            conn->parser.request_parser.cantBytes = 0;

            char *response;
            char *command = strtok(conn->parser.request_parser.text, " \r\n");
            if(command && strcmp(command, "USERS") == 0) {
                if(!permission_user_command(conn->cur_user, "USERS")) {
                    response = "403 Forbidden: Insufficient permissions\n";
                    state = METP_REQUEST_RESPONSE;
                } else {
                    char * user_list = get_user_list();
                    metp_200(key);
                    if(*user_list){
                        return NULL;
                    }
                }
            }
        }
        

    }
    return METP_REQUEST;
}


static void metp_200(struct selector_key * key){
    metp_connection_t * connection = key->data;
    const char * message = "200 OK\n";
    size_t m;
    uint8_t * tor = buffer_write_ptr(connection->buffer_w, &m);
    size_t l = strlen(message);
    memcpy(tor, message, l);
    buffer_write_adv(connection->buffer_w, l);
    selector_set_interest_key(key, OP_WRITE);

}


static unsigned metp_request_response_write(struct selector_key * key) {
    metp_connection_t *connection = (metp_connection_t *)key->data;
    
    size_t bytes;
    uint8_t *src = buffer_read_ptr(connection->buffer_w, &bytes);

    if (bytes > 0) {
        ssize_t sent = send(connection->fd_client, src, bytes, MSG_NOSIGNAL);
        if (sent > 0) {
            buffer_read_adv(connection->buffer_w, sent);
        } else{
            perror("send() in metp_request_response_write");
            return METP_ERROR;
        }
    }
    
    if (connection->sending && !buffer_can_read(connection->buffer_w)) {
        if (connection->to_send_remaining > 0) {
            size_t wcap;
            uint8_t *out = buffer_write_ptr(connection->buffer_w, &wcap);
            size_t to_send = connection->to_send_remaining;
            
            if (to_send > wcap) to_send = wcap;
            
            if (to_send > 0) {
                memcpy(out, connection->to_send, to_send);
                buffer_write_adv(connection->buffer_w, to_send);
                connection->to_send += to_send;
                connection->to_send_remaining -= to_send;
            }
            
            return METP_REQUEST_RESPONSE; 
        } else {
            connection->sending = false; 
        }
    }
    
    // Si terminamos de enviar todo
    if (!buffer_can_read(connection->buffer_w)) {
        if (connection->close) {
            close(connection->fd_client);
            return METP_TERMINATED;
        } else {
            selector_set_interest_key(key, OP_READ);
            return METP_REQUEST;
        }
    }
    
    return METP_REQUEST_RESPONSE;
}