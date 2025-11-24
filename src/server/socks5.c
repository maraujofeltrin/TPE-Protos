#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "include/socks5.h"
#include "selector.h"

//VER SI FALTAN MAS
static const struct state_definition socks5_states_def[] = {
    [HANDSHAKE] = {
        .state = HANDSHAKE,
        .on_arrival = socks5_handshake_on_arrival,
        .on_read_ready = socks5_handshake_on_read,
    },
    [HANDSHAKE_RESPONSE] = {
        .state = HANDSHAKE_RESPONSE,
        .on_write_ready = socks5_handshake_response_on_write,
    },/*
    [REQUEST] = {
        .state = REQUEST,
        .on_arrival = socks5_request_on_arrival,
        .on_read_ready = socks5_request_on_read,
    },
    [REQUEST_RESPONSE] = {
        .state = REQUEST_RESPONSE,
        .on_arrival = socks5_request_response_on_arrival,
        .on_read_ready = socks5_request_response_on_read,
    },
    [ERROR] = {
        .state = ERROR,
        .on_read_ready = socks5_error_on_read,
        .on_write_ready = socks5_error_on_write,
    },
    [CLOSED] = {
        .state = CLOSED,
        .on_read_ready = socks5_closed_on_read,
        .on_write_ready = socks5_closed_on_write,
    },
    [REQUEST_CONNECT] = {
        .state = REQUEST_CONNECT,
        .on_write_ready = socks5_request_connect_on_write,
    },
    [REQUEST_BIND] = {
        .state = REQUEST_BIND,
        .on_write_ready = socks5_request_bind_on_write,
    },
    [AUTHENTICATION] = {
        .state = AUTHENTICATION,
        .on_arrival = socks5_authentication_on_arrival,
        .on_read_ready = socks5_authentication_on_read,
    },
    [AUTHENTICATION_RESPONSE] = {
        .state = AUTHENTICATION_RESPONSE,
        .on_write_ready = socks5_authentication_response_on_write,
    }*/
};

static void socks5_handshake_on_arrival(struct selector_key *key) {
    socks5_connection_t * connection = key->data;
    connection->parser.handshake.bytes_read = 0;
    connection->parser.handshake.bytes_written = 0;
    connection->parser.handshake.request.version = SOCKS5_VERSION;
    connection->parser.handshake.request.nmethods = 0;
    connection->parser.handshake.response.version = SOCKS5_VERSION;
    connection->parser.handshake.response.method = HANDSHAKE_METHOD_NO_ACCEPTABLE;
}

static unsigned socks5_handshake_on_read(struct selector_key *key) {
    socks5_connection_t * connection = key->data;
    handshake_context_t * handshake = &connection->parser.handshake;
    buffer * b = &connection->read_b;
    
    size_t bytes;
    uint8_t * des = buffer_write_ptr(b, &bytes);
    size_t rec = recv(key->fd, des, bytes, 0);

    if(rec < 0){
        perror("recv");
        return ERROR;
    }
    else if (rec == 0){
        return CLOSED;
    }
    else{
        buffer_write_adv(b, rec);
    }

    size_t disp;
    uint8_t * buf = buffer_read_ptr(b, &disp);
    while(disp > 0){
        uint8_t aux = *buf;
        switch(handshake->bytes_read){
            case 0:
                if((handshake->request.version = aux) != SOCKS5_VERSION){
                    return ERROR;
                }
                break;
            case 1:
                if((handshake->request.nmethods = aux) == 0){
                    return ERROR;
                }
                break;
            default:
                if(handshake->bytes_read - 2 < handshake->request.nmethods){
                    handshake->request.methods[handshake->bytes_read - 2] = aux;
                }
                break;    
        }
        handshake->bytes_read++;
        buffer_read_adv(b, 1);
        disp--;
        buf++;

        if(handshake->bytes_read == 2 + handshake->request.nmethods){
            handshake->response.version = SOCKS5_VERSION;
            handshake->response.method = HANDSHAKE_METHOD_NO_ACCEPTABLE;
            
            for(uint8_t i = 0; i < handshake->request.nmethods; i++){
                if(handshake->request.methods[i] == AUTH_USER){
                    handshake->response.method = AUTH_USER;
                    break;
                }
            }

            uint8_t resp[2] = {handshake->response.version, handshake->response.method};
            for(size_t i = 0; i < 2; i++){
                buffer_write(&connection->write_b, resp[i]);
            }
            selector_set_interest_key(key, OP_WRITE);
            return (handshake->response.method == HANDSHAKE_METHOD_NO_ACCEPTABLE) ? ERROR : HANDSHAKE_RESPONSE;
        }
    }

    return HANDSHAKE;
}



static unsigned socks5_handshake_response_on_write(struct selector_key *key) {
    socks5_connection_t * connection = key->data;
    buffer * b = &connection->write_b;
    size_t bytes;
    uint8_t * src = buffer_read_ptr(b, &bytes);
    size_t sent = send(key->fd, src, bytes, MSG_NOSIGNAL);
    if(sent <= 0){
        return CLOSED;
    }
    buffer_read_adv(b, sent);

    //VER , FALTA LA PARTE DE AUTENTICACIÓN
    if(!buffer_can_read(b)){
        selector_set_interest_key(key, OP_READ);
        if(connection->parser.handshake.response.method /*NO_AUTHENTICATION_REQUIRED*/){
            return REQUEST;
        }
        else{
            return ;
        }
    }
    return HANDSHAKE_RESPONSE;
}

static unsigned socks5_authentication_on_arrival(struct selector_key *key) {
    socks5_connection_t * connection = key->data;
    connection->parser.handshake.bytes_read = 0;
    connection->parser.handshake.bytes_written = 0;
    return AUTHENTICATION;
}
