#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "selector.h"
#include "../include/s5mp.h"
#include "../include/users.h"
#include "../include/metrics.h"


static unsigned send_response(struct selector_key *key, const char *message, unsigned next_state);
static void write_message_to_buffer(buffer *, const char *message);
static unsigned s5mp_handshake_read(struct selector_key * key);
static unsigned s5mp_handshake_response_write(struct selector_key * key);
static unsigned s5mp_write_auth(struct selector_key * key);
static unsigned s5mp_read_auth(struct selector_key * key);
static unsigned s5mp_request_read(struct selector_key * key);
static void s5mp_request_arrival(const unsigned state, struct selector_key * key);
static unsigned s5mp_request_response_write(struct selector_key * key);
static void s5mp_error_arrival(const unsigned state, struct selector_key * key);
static unsigned s5mp_error_write(struct selector_key * key);
static void s5mp_200(struct selector_key * key);

static size_t buffer_size = BUFFER_MAX;


static const struct state_definition s5mp_states_def[] = {
    [S5MP_HANDSHAKE] = {
        .state = S5MP_HANDSHAKE,
        .on_read_ready = s5mp_handshake_read,
    },
    [S5MP_HANDSHAKE_RESPONSE] = {
        .state = S5MP_HANDSHAKE_RESPONSE,
        .on_write_ready = s5mp_handshake_response_write,
    },
    [S5MP_AUTH] = {
        .state = S5MP_AUTH,
        .on_read_ready = s5mp_read_auth,
    },
    [S5MP_AUTH_RESPONSE] = {
        .state = S5MP_AUTH_RESPONSE,
        .on_write_ready = s5mp_write_auth,
    },
    [S5MP_REQUEST] = {
        .state = S5MP_REQUEST,
        .on_arrival = s5mp_request_arrival,
        .on_read_ready = s5mp_request_read,
    },
    [S5MP_REQUEST_RESPONSE] = {
        .state = S5MP_REQUEST_RESPONSE,
        .on_write_ready = s5mp_request_response_write, 
    },
    [S5MP_TERMINATED] = {
        .state = S5MP_TERMINATED,
    },
    [S5MP_ERROR] = {
        .state = S5MP_ERROR,
        .on_arrival = s5mp_error_arrival, 
        .on_write_ready = s5mp_error_write,
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
    s5mp_connection_t *conn = (s5mp_connection_t *)key->data;
    if (!conn || !conn->buffer_w) return S5MP_ERROR;
    
    write_message_to_buffer(conn->buffer_w, message);
    selector_set_interest_key(key, OP_WRITE);
    return next_state;
}

const struct state_definition * get_s5mp_state_definition() {
    return s5mp_states_def;
}

static unsigned s5mp_handshake_read(struct selector_key * key) {
    s5mp_connection_t * connection = key->data;
    size_t cant;    
    unsigned state = S5MP_HANDSHAKE;
    uint8_t *ptr = buffer_write_ptr(connection->buffer_r, &cant);
    ssize_t n = recv(connection->fd_client, ptr, cant, 0);

    if(n <= 0) {
        perror("s5mp handshake recv");
        return S5MP_ERROR;
    }
    buffer_write_adv(connection->buffer_r, (size_t)n);
    
    uint8_t a;
    while(buffer_can_read(connection->buffer_r)) {
        a = buffer_read(connection->buffer_r);
        
        if(connection->parser.auth_parser.cantBytes < BUFFER_MAX - 1) {
            connection->parser.auth_parser.text[connection->parser.auth_parser.cantBytes++] = (char)a;
        }
        else{
            return send_response(key, "400 Bad Request: Line too long\n", S5MP_ERROR);
        }

        if(a == '\n' || connection->parser.auth_parser.cantBytes == BUFFER_MAX - 1) {
            connection->parser.auth_parser.text[connection->parser.auth_parser.cantBytes] = '\0';
            connection->parser.auth_parser.cantBytes = 0;
            char * resp;
            size_t m, l;
            uint8_t * tor;
            //VER DE MODULARIZAR PARA NO REPETIR
            if(strcmp(connection->parser.auth_parser.text, "HELLO S5MP/1.0\n") == 0) {
                resp = "200 S5MP Handshake Successful\n";
                tor = buffer_write_ptr(connection->buffer_w, &m);
                l = strlen(resp);
                if(l > m) {
                    l = m;
                }
                memcpy(tor, resp, l);
                buffer_write_adv(connection->buffer_w, l);
                selector_set_interest_key(key, OP_WRITE);
                state = S5MP_HANDSHAKE_RESPONSE;
                break;  // Salir del loop - no procesar más líneas
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
                state = S5MP_ERROR;
                break;  // Salir del loop
            }
        }
    }
    return state;
}

static unsigned s5mp_handshake_response_write(struct selector_key * key) {
    s5mp_connection_t * connection = key->data;
    size_t c;
    uint8_t *src = buffer_read_ptr(connection->buffer_w, &c);
    if(c <= 0){
        return S5MP_ERROR;
    }
    
    ssize_t s = send(connection->fd_client, src, c, 0);

    if(s <= 0){
        return S5MP_ERROR;
    }

    buffer_read_adv(connection->buffer_w, (size_t)s);

    if(!buffer_can_read(connection->buffer_w)){
        selector_set_interest_key(key, OP_READ);
        return S5MP_AUTH;
    }

    return S5MP_HANDSHAKE_RESPONSE;
}


static void s5mp_error_arrival(const unsigned state, struct selector_key * key) {
    (void) state;
    s5mp_connection_t * connection = key->data;

    if(!buffer_can_read(connection->buffer_w)){
        write_message_to_buffer(connection->buffer_w, "500 Internal Server Error\n");
    }
    selector_set_interest_key(key, OP_WRITE);
}

static unsigned s5mp_error_write(struct selector_key * key) {
    s5mp_connection_t * connection = key->data;
    
    size_t bytes;
    uint8_t *src = buffer_read_ptr(connection->buffer_w, &bytes);
    
    if (bytes > 0) {
        ssize_t sent = send(connection->fd_client, src, bytes, MSG_NOSIGNAL);
        if (sent > 0) {
            buffer_read_adv(connection->buffer_w, sent);
        }
    }
    
    // Retornar TERMINATED - el wrapper s5mp_handle_write llamará a close
    return S5MP_TERMINATED;
}

static unsigned s5mp_read_auth(struct selector_key * key) {
    s5mp_connection_t *conn = (s5mp_connection_t *)key->data;
    if(!conn || !conn->buffer_r || !conn->buffer_w) return S5MP_ERROR;

    buffer *rb = conn->buffer_r;
    
    // Solo hacer recv si no hay datos pendientes en el buffer
    if(!buffer_can_read(rb)) {
        size_t avail;
        uint8_t *in = buffer_write_ptr(rb, &avail);
        ssize_t n = recv(key->fd, in, avail, 0);
        if (n <= 0) {
            perror("s5mp recv");
            return S5MP_ERROR;
        }
        buffer_write_adv(rb, (size_t)n);
    }
    
    while (buffer_can_read(rb)) {
        uint8_t c = buffer_read(rb);
        size_t idx = conn->parser.auth_parser.cantBytes;
        if (idx >= BUFFER_MAX - 1) {
            return send_response(key, "400 Bad Request: Line too long\n", S5MP_ERROR);
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
                    return send_response(key, "400 Bad Request: Missing user or password\n", S5MP_ERROR);
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
                return S5MP_AUTH_RESPONSE;
            }

            return send_response(key, "400 Bad Request\n", S5MP_ERROR);
        }
    }

    return S5MP_AUTH;
}

static unsigned s5mp_write_auth(struct selector_key * key) {
    s5mp_connection_t *conn = (s5mp_connection_t *)key->data;
    if (!conn || !conn->buffer_w) return S5MP_ERROR;

    buffer *wb = conn->buffer_w;
    size_t bytes;
    uint8_t *src = buffer_read_ptr(wb, &bytes);
    ssize_t sent = send(key->fd, src, bytes, MSG_NOSIGNAL);
    if (sent <= 0) {
        return S5MP_ERROR;
    }
    buffer_read_adv(wb, sent);
    if (!buffer_can_read(wb)) {
        if (conn->authenticated) {
            selector_set_interest_key(key, OP_READ);
            return S5MP_REQUEST;
        } else {
            close(conn->fd_client);
            return S5MP_TERMINATED;
        }
    }
    return S5MP_AUTH_RESPONSE;
}

static void s5mp_request_arrival(const unsigned state, struct selector_key * key) {
    (void)state;
    s5mp_connection_t *conn = (s5mp_connection_t *)key->data;
    conn->parser.request_parser.cantBytes = 0;
    conn->parser.request_parser.text[0] = '\0';
    selector_set_interest_key(key, OP_READ);
}

static unsigned s5mp_request_read(struct selector_key * key) {
    s5mp_connection_t *conn = (s5mp_connection_t *)key->data;
    buffer *rb = conn->buffer_r;
    unsigned int state = S5MP_ERROR;
    size_t avail;
    uint8_t *in = buffer_write_ptr(rb, &avail);
    ssize_t n = recv(key->fd, in, avail, 0);
    if (n < 0) {
        perror("s5mp recv");
        char * response = "500 Internal Server Error\n";
        write_message_to_buffer(conn->buffer_w, response);
        selector_set_interest_key(key, OP_WRITE);
        return S5MP_ERROR;
    }
    if(n == 0) {
        conn->close = true;
        selector_set_interest_key(key, OP_WRITE);
        return S5MP_REQUEST_RESPONSE;
    }
    buffer_write_adv(rb, (size_t)n);
    while (buffer_can_read(rb)) {
        uint8_t c = buffer_read(rb);
        size_t idx = conn->parser.request_parser.cantBytes;
        if (idx >= BUFFER_MAX - 1) {
            send_response(key, "400 Bad Request: Line too long\n",  S5MP_ERROR);
            selector_set_interest_key(key, OP_WRITE);
            return  S5MP_REQUEST_RESPONSE;
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
                    write_message_to_buffer(conn->buffer_w, response);
                    state = S5MP_REQUEST_RESPONSE;
                } else {
                    const char * user_list = get_user_list();
                    s5mp_200(key);
                    if(*user_list){
                        size_t amount;
                        uint8_t * tor = buffer_write_ptr(conn->buffer_w, &amount);
                        size_t l = strlen(user_list);
                        if(l > amount) {
                            l = amount;
                        }
                        memcpy(tor, user_list, l);
                        buffer_write_adv(conn->buffer_w, l);
                    } else{
                        char * no_users = "\n";
                        size_t amount;
                        uint8_t * tor = buffer_write_ptr(conn->buffer_w, &amount);
                        size_t l = 2;
                        if(l > amount) {
                            l = amount;
                        }
                        memcpy(tor, no_users, l);
                        buffer_write_adv(conn->buffer_w, l);
                    }
                    state = S5MP_REQUEST_RESPONSE;
                }
            }
            else if(command && strcmp(command, "ADD_USER") == 0) {
                char * user_to_add = strtok(NULL, " \r\n");
                char * pass_to_add = strtok(NULL, " \r\n");
                if(!user_to_add || !pass_to_add) {
                    response = "400 Bad Request: Missing username or password to add\n";
                    write_message_to_buffer(conn->buffer_w, response);
                    state = S5MP_REQUEST_RESPONSE;
                } else if(!permission_user_command(conn->cur_user, "ADD_USER")) {
                    response = "403 Forbidden: Insufficient permissions\n";
                    write_message_to_buffer(conn->buffer_w, response);
                    state = S5MP_REQUEST_RESPONSE;
                } else {
                    bool added = users_add(user_to_add, pass_to_add, ROLE_USER) == 0;
                    if(added) {
                        response = "200 OK: User added successfully\n";
                    } else {
                        response = "409 Conflict: User already exists\n";
                    }
                    write_message_to_buffer(conn->buffer_w, response);
                    state = S5MP_REQUEST_RESPONSE;
                }
            }else if(command && strcmp(command, "ROLE_SETTER")== 0){
                char * user_to_set = strtok(NULL, " \r\n");
                char * role_str = strtok(NULL, " \r\n");
                if(!user_to_set || !role_str) {
                    response = "400 Bad Request: Missing username or role to set\n";
                    write_message_to_buffer(conn->buffer_w, response);
                    state = S5MP_REQUEST_RESPONSE;
                } else if(!permission_user_command(conn->cur_user, "ROLE_SETTER")) {
                    response = "403 Forbidden: Insufficient permissions\n";
                    write_message_to_buffer(conn->buffer_w, response);
                    state = S5MP_REQUEST_RESPONSE;
                } else {
                    user_role_t new_role;
                    if(strcmp(role_str, "ADMIN") == 0) {
                        new_role = ROLE_ADMIN;
                    } else if(strcmp(role_str, "USER") == 0) {
                        new_role = ROLE_USER;
                    } else {
                        response = "400 Bad Request: Invalid role specified\n";
                        write_message_to_buffer(conn->buffer_w, response);
                        state = S5MP_REQUEST_RESPONSE;
                        continue;
                    }
                    user_t * user = find_user_by_name(user_to_set);
                    if(user) {
                        user->role = new_role;
                        response = "200 OK: User role updated successfully\n";
                    } else {
                        response = "404 Not Found: User does not exist\n";
                    }
                    write_message_to_buffer(conn->buffer_w, response);
                    state = S5MP_REQUEST_RESPONSE;
                }
            }else if(command && strcmp(command, "BUFFER_NEWSIZE")==0){
                char * size_str = strtok(NULL, " \r\n");
                if(!size_str) {
                    response = "400 Bad Request: Missing buffer size\n";
                    write_message_to_buffer(conn->buffer_w, response);
                    state = S5MP_REQUEST_RESPONSE;
                } else if(!permission_user_command(conn->cur_user, "BUFFER_NEWSIZE")) {
                    response = "403 Forbidden: Insufficient permissions\n";
                    write_message_to_buffer(conn->buffer_w, response);
                    state = S5MP_REQUEST_RESPONSE;
                } else{
                    size_t new_size = (size_t)atoi(size_str);
                    if(new_size == 0 || new_size > BUFFER_MAX) {
                        response = "400 Bad Request: Invalid buffer size\n";
                    } else {
                        buffer_size = new_size;
                        response = "200 OK: Buffer size updated successfully\n";
                    }
                    write_message_to_buffer(conn->buffer_w, response);
                    state = S5MP_REQUEST_RESPONSE;
                }
            }
            else if(command && strcmp(command, "DELETE_USER") == 0) {
                char * user_to_delete = strtok(NULL, " \r\n");
                if(!user_to_delete) {
                    response = "400 Bad Request: Missing username to delete\n";
                    write_message_to_buffer(conn->buffer_w, response);
                    state = S5MP_REQUEST_RESPONSE;
                } else if(!permission_user_command(conn->cur_user, "DELETE_USER")) {
                    response = "403 Forbidden: Insufficient permissions\n";
                    write_message_to_buffer(conn->buffer_w, response);
                    state = S5MP_REQUEST_RESPONSE;
                } else {
                    bool deleted = remove_user(user_to_delete) == 0;
                    if(deleted) {
                        response = "200 OK: User deleted successfully\n";
                    } else {
                        response = "404 Not Found: User does not exist\n";
                    }
                    write_message_to_buffer(conn->buffer_w, response);
                    state = S5MP_REQUEST_RESPONSE;
                }
            }else if(command && strcmp(command, "QUIT") == 0) {
                response = "200 OK: Closing connection\n";
                write_message_to_buffer(conn->buffer_w, response);
                conn->close = true;
                state = S5MP_REQUEST_RESPONSE;
            }else if(strcmp(command, "GET_LOGS") == 0){
                if(!permission_user_command(conn->cur_user, "GET_LOGS")) {
                    response = "403 Forbidden: Insufficient permissions\n";
                    write_message_to_buffer(conn->buffer_w, response);
                    state = S5MP_REQUEST_RESPONSE;
                } else {
                    const char * logs = get_all_logs();
                    s5mp_200(key);
                    if(*logs){
                        size_t amount;
                        uint8_t * tor = buffer_write_ptr(conn->buffer_w, &amount);
                        size_t l = strlen(logs);
                        if(l > amount) {
                            l = amount;
                        }
                        memcpy(tor, logs, l);
                        buffer_write_adv(conn->buffer_w, l);
                    } else{
                        char * no_logs = "\n";
                        size_t amount;
                        uint8_t * tor = buffer_write_ptr(conn->buffer_w, &amount);
                        size_t l = 2;
                        if(l > amount) {
                            l = amount;
                        }
                        memcpy(tor, no_logs, l);
                        buffer_write_adv(conn->buffer_w, l);
                    }
                    state = S5MP_REQUEST_RESPONSE;
                }
            }else if (command && strcmp(command, "GET_METRICS") == 0) {
                if (!permission_user_command(conn->cur_user, "GET_ALL_METRICS")) {
                    response = "403 Forbidden: Insufficient permissions\n";
                    write_message_to_buffer(conn->buffer_w, response);
                    state = S5MP_REQUEST_RESPONSE;
                } else {
                    char metrics[256];
                    int length = snprintf(metrics, sizeof(metrics),
                        "active_connections %ld\ntotal_connections %ld\ntotal_bytes_transferred %ld\n.\n",
                        metrics_get_active_connections(),
                        metrics_get_total_connections(),
                        metrics_get_total_data_transferred()
                    );
                    if (length > 0 && (size_t)length < sizeof(metrics)) {
                        s5mp_200(key);
                        size_t amount;//VER LO DE ADENTRO DEL IF
                        uint8_t * tor = buffer_write_ptr(conn->buffer_w, &amount);
                        size_t l = (size_t)length;
                        if(l > amount) {
                            l = amount;
                        }
                        memcpy(tor, metrics, l);
                        buffer_write_adv(conn->buffer_w, l);
                        state = S5MP_REQUEST_RESPONSE;
                    }
                    else {
                        return send_response(key, "500 Internal Server Error\n", S5MP_ERROR);
                    }
                    
                }
            }
            else {
                response = "400 Bad Request: Unknown Command\n";
                write_message_to_buffer(conn->buffer_w, response);
                state = S5MP_REQUEST_RESPONSE;
            }
            conn->parser.request_parser.cantBytes = 0;
            break;
        }
        
    }
    selector_set_interest_key(key, OP_WRITE);
    return state;
}


static void s5mp_200(struct selector_key * key){
    s5mp_connection_t * connection = key->data;
    const char * message = "200 OK\n";
    size_t m;
    uint8_t * tor = buffer_write_ptr(connection->buffer_w, &m);
    size_t l = strlen(message);
    memcpy(tor, message, l);
    buffer_write_adv(connection->buffer_w, l);
    selector_set_interest_key(key, OP_WRITE);
}

static unsigned s5mp_request_response_write(struct selector_key * key) {
    s5mp_connection_t *connection = (s5mp_connection_t *)key->data;
    
    size_t bytes;
    uint8_t *src = buffer_read_ptr(connection->buffer_w, &bytes);

    if (bytes > 0) {
        ssize_t sent = send(connection->fd_client, src, bytes, MSG_NOSIGNAL);
        if (sent > 0) {
            buffer_read_adv(connection->buffer_w, sent);
        } else{
            perror("send() in s5mp_request_response_write");
            return S5MP_ERROR;
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
            
            return S5MP_REQUEST_RESPONSE; 
        } else {
            connection->sending = false; 
        }
    }
    
    // Si terminamos de enviar todo
    if (!buffer_can_read(connection->buffer_w)) {
        if (connection->close) {
            close(connection->fd_client);
            return S5MP_TERMINATED;
        } else {
            selector_set_interest_key(key, OP_READ);
            return S5MP_REQUEST;
        }
    }
    
    return S5MP_REQUEST_RESPONSE;
}

size_t get_s5mp_buffer_size() {
    return buffer_size;
}