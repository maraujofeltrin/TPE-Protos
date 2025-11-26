#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "selector.h"
#include "include/metp.h"
#include "include/users.h"

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
        .on_arrival = metp_read,
        .on_read_ready = metp_read
    },
    [METP_REQUEST_RESPONSE] = {
        .state = METP_REQUEST_RESPONSE,
        .on_write_ready = metp_write
    },
    [METP_TERMINATED] = {
        .state = METP_TERMINATED,
    },
    [METP_ERROR] = {
        .state = METP_ERROR,
        .on_arrival = metp_error_arrival,

    }
};

const struct state_definition * get_metp_state_definition() {
    return metp_states_def;
}

static unsigned metp_handshake_read(struct selector_key *key) {
    (void)key;
    return METP_HANDSHAKE;
}

static unsigned metp_handshake_response_write(struct selector_key *key) {
    (void)key;
    return METP_HANDSHAKE_RESPONSE;
}

static unsigned metp_write_auth(struct selector_key *key);

static void metp_error_arrival(const unsigned state, struct selector_key *key) {
    (void)state;
}

static unsigned metp_read_auth(struct selector_key *key) {
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
            const char *msg = "400 Bad Request: Line too long\n";
                for (size_t j = 0; j < strlen(msg); ++j) buffer_write(conn->buffer_w, (uint8_t)msg[j]);
            selector_set_interest_key(key, OP_WRITE);
            return METP_ERROR;
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
                    const char *msg = "400 Bad Request: Missing user or password\n";
                        for (size_t j = 0; j < strlen(msg); ++j) buffer_write(conn->buffer_w, (uint8_t)msg[j]);
                    selector_set_interest_key(key, OP_WRITE);
                    return METP_ERROR;
                }

                user_t *u = authenticate_user(user, pass);
                if (u) {
                    conn->authenticated = true;
                    strncpy(conn->cur_user, user, USER_MAX - 1);
                    conn->cur_user[USER_MAX - 1] = '\0';
                    const char *ok = "200 OK\n";
                        for (size_t j = 0; j < strlen(ok); ++j) buffer_write(conn->buffer_w, (uint8_t)ok[j]);
                } else {
                    const char *una = "401 Unauthorized. Closing connection.\n";
                        for (size_t j = 0; j < strlen(una); ++j) buffer_write(conn->buffer_w, (uint8_t)una[j]);
                    conn->close = true;
                }

                selector_set_interest_key(key, OP_WRITE);
                return METP_AUTH_RESPONSE;
            }

            const char *bad = "400 Bad Request\n";
                for (size_t j = 0; j < strlen(bad); ++j) buffer_write(conn->buffer_w, (uint8_t)bad[j]);
            selector_set_interest_key(key, OP_WRITE);
            return METP_ERROR;
        }
    }

    return METP_AUTH;
}

static unsigned metp_write_auth(struct selector_key *key) {
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
        /* If authentication succeeded, go to command state; otherwise close */
        if (conn->authenticated) {
            selector_set_interest_key(key, OP_READ);
            return METP_REQUEST;
        } else {
            //VER, FALTA CERRAR CONEXION
            return METP_TERMINATED;
        }
    }
    return METP_AUTH_RESPONSE;
}

