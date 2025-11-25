#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

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
    },
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
    }
};

static void socks5_handshake_on_arrival(struct selector_key * key) {
    socks5_connection_t * connection = key->data;
    connection->parser.handshake.bytes_read = 0;
    connection->parser.handshake.bytes_written = 0;
    connection->parser.handshake.request.version = SOCKS5_VERSION;
    connection->parser.handshake.request.nmethods = 0;
    connection->parser.handshake.response.version = SOCKS5_VERSION;
    connection->parser.handshake.response.method = HANDSHAKE_METHOD_NO_ACCEPTABLE;
}

static unsigned socks5_handshake_on_read(struct selector_key * key) {
    socks5_connection_t * connection = key->data;
    handshake_context_t * handshake = &connection->parser.handshake;
    buffer * b = &connection->read_c;
    
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
                buffer_write(&connection->write_c, resp[i]);
            }
            selector_set_interest_key(key, OP_WRITE);
            return (handshake->response.method == HANDSHAKE_METHOD_NO_ACCEPTABLE) ? ERROR : HANDSHAKE_RESPONSE;
        }
    }

    return HANDSHAKE;
}



static unsigned socks5_handshake_response_on_write(struct selector_key * key) {
    socks5_connection_t * connection = key->data;
    buffer * b = &connection->write_p;
    size_t bytes;
    uint8_t * src = buffer_read_ptr(b, &bytes);
    size_t sent = send(key->fd, src, bytes, MSG_NOSIGNAL);
    if(sent <= 0){
        return CLOSED;
    }
    buffer_read_adv(b, sent);
    if(!buffer_can_read(b)){
        selector_set_interest_key(key, OP_READ);
        if(connection->parser.handshake.response.method == NO_AUTH){
            return REQUEST;
        }
        else{
            return AUTHENTICATION;
        }
    }
    return HANDSHAKE_RESPONSE;
}

static void socks5_authentication_on_arrival(struct selector_key * key) {
    socks5_connection_t * connection = key->data;
    authenticaction_initialize(&connection->parser.authentication);
}

static unsigned socks5_authentication_on_read(struct selector_key * key) {
    socks5_connection_t * connection = key->data;
    buffer * b = &connection->read_c;
    authentication_context_t * auth_ctx = &connection->parser.authentication;
    size_t bytes;
    uint8_t * des = buffer_write_ptr(b, &bytes);
    size_t rec = recv(key->fd, des, bytes, 0);
    if(rec == 0){
        return CLOSED;
    }
    else if(rec < 0){
        perror("recv error");
        return ERROR;
    }
    else{
        buffer_write_adv(b, rec);
    }

    bool error = false;
    auth_index res = authentication_parse(&connection->parser.authentication, b, &error);
    if(error){
        selector_set_interest_key(key, OP_WRITE);
        return AUTHENTICATION_RESPONSE;
    }
    if(res == AUTH_COMPLETED){
        //VER SI HAY QUE VALIDAR USUARIO Y CONTRASEÑA
        selector_set_interest_key(key, OP_WRITE);
        return AUTHENTICATION_RESPONSE;
    }
    return AUTHENTICATION;
}

static unsigned socks5_authentication_response_on_write(struct selector_key * key) {
    socks5_connection_t * connection = key->data;
    authentication_context_t * auth_ctx = &connection->parser.authentication;
    buffer * b = &connection->write_p;

    size_t bytes;
    uint8_t * src = buffer_read_ptr(b, &bytes);
    size_t sent = send(key->fd, src, bytes, MSG_NOSIGNAL);
    if(sent <= 0){
        return CLOSED;
    }
    buffer_read_adv(b, sent);
    if(!buffer_can_read(b)){
        if(auth_ctx->response.status == AUTH_FAILED){
            return CLOSED;
        }
        else{
            selector_set_interest_key(key, OP_READ);
            return REQUEST;
        }
    }
    return AUTHENTICATION_RESPONSE;
}

static void socks5_request_on_arrival(struct selector_key * key){
    selector_set_interest_key(key, OP_READ);
}

static void * dns_resolve_thread(void * arg){
    //VER ESTO   
}

static unsigned socks5_request_on_read(struct selector_key * key){
    socks5_connection_t * connection = key->data;
    buffer * b = &connection->read_c;

    size_t bytes;
    uint8_t * des = buffer_write_ptr(b, &bytes);
    size_t rec = recv(key->fd, des, bytes, 0);
    if(rec == 0){
        return CLOSED;
    }
    else if(rec < 0){
        perror("recv");
        return ERROR;
    }
    else{
        buffer_write_adv(b, rec);
    }

    size_t disp;
    uint8_t * buf = buffer_read_ptr(b, &disp);
    size_t ocu = 0;
    int res = parse_socks5_request(&connection->parser.request, buf, disp, &ocu);

    if(res == 0){
        buffer_read_adv(b, ocu);
        switch(connection->parser.request.request.command){
            case REQUEST_CONNECT:
                switch(connection->parser.request.request.dest_address.atyp){
                    case SOCKS5_ATYP_IPV4:
                        connection->remote_domain = AF_INET;
                        connection->remote_address_len = sizeof(struct sockaddr_in);
                        struct sockaddr_in * address_in4 = (struct sockaddr_in *)&connection->remote_address;

                        address_in4->sin_family = AF_INET;
                        memcpy(&address_in4->sin_addr, connection->parser.request.request.dest_address.address.ipv4, 4);
                        address_in4->sin_port = htons(connection->parser.request.request.dest_address.port);
                        
                        char ip4_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, connection->parser.request.request.dest_address.address, ip4_str, INET_ADDRSTRLEN);
                        return /*//VER DE INICIALIZAR REMOTE CONECTION*/;

                    case SOCKS5_ATYP_DOMAINNAME:
                        struct selector_key *sk = malloc(sizeof(struct selector_key));
                        *sk = *key;
                        pthread_t dns_thread;
                        if(pthread_create(&dns_thread, NULL, dns_resolve_thread, sk) != 0){
                            free(sk);
                            return ERROR;
                        }
                        pthread_detach(dns_thread);
                        selector_set_interest_key(key, OP_NOOP);
                        return REQUEST_CONNECT;

                    case SOCKS5_ATYP_IPV6:
                        connection->remote_domain = AF_INET6;
                        connection->remote_address_len = sizeof(struct sockaddr_in6);
                        struct sockaddr_in6 * address_in6 = (struct sockaddr_in6 *)&connection->remote_address;

                        address_in6->sin6_family = AF_INET6;
                        memcpy(&address_in6->sin6_addr, connection->parser.request.request.dest_address.address.ipv6, 16);
                        address_in6->sin6_port = htons(connection->parser.request.request.dest_address.port);

                        char ip6_str[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, connection->parser.request.request.dest_address.address, ip6_str, INET6_ADDRSTRLEN);
                        return /*//VER DE INICIALIZAR REMOTE CONECTION*/;
                }
            case REQUEST_BIND:
                selector_set_interest_key(key, OP_WRITE);
                return REQUEST_BIND;
            default:
                return ERROR;
        }
    }
    return REQUEST;
}

static void socks5_request_response_on_arrival(struct selector_key * key){
    selector_set_interest_key(key, OP_READ);
}

static unsigned socks5_request_response_on_read(struct selector_key * key){
    socks5_connection_t * connection = key->data;
    struct addrinfo * resp = connection->req_address;
    struct addrinfo * cur = resp;
    
    //VER EL WHILE PQ REALMENTE NO CICLA PERO PODRIA 
    while(cur != NULL){
        connection->remote_domain = cur->ai_family;
        connection->remote_address_len = cur->ai_addrlen;
        memcpy(&connection->remote_address, cur->ai_addr, cur->ai_addrlen);

        freeaddrinfo(resp);
        connection->req_address = NULL;
        socks5_response_parser_t reply= {
            .version = SOCKS5_VERSION,
            .response = SOCKS5_REP_HOST_UNREACHABLE,
            .reserved = 0x00,
            .add = (connection->remote_domain == AF_INET) ? SOCKS5_ATYP_IPV4 : SOCKS5_ATYP_IPV6
        };
        memset(&reply.dest_address, 0, sizeof(reply.dest_address));
        reply.dest_address.port = 0;

        //VER DE TERMINAR ESTO !!!!!!!!

        return /*//VER DE INICIALIZAR REMOTE CONNECTION*/;
    }

    freeaddrinfo(resp);
    connection->req_address = NULL;
    
    selector_set_interest_key(key, OP_WRITE);
    return CLOSED;
}
