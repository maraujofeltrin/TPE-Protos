#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "include/socks5.h"
#include "selector.h"
#include "include/authentication.h"
#include "include/users.h"
#include "include/builder.h"


// Declaraciones de funciones static
static void socks5_handshake_on_arrival(const unsigned int state, struct selector_key * key);
static unsigned socks5_handshake_on_read(struct selector_key * key);
static unsigned socks5_handshake_response_on_write(struct selector_key * key);
static void socks5_authentication_on_arrival(const unsigned int state, struct selector_key * key);
static unsigned socks5_authentication_on_read(struct selector_key * key);
static unsigned socks5_authentication_response_on_write(struct selector_key * key);
static unsigned socks5_error_on_read();
static unsigned socks5_error_on_write();
static unsigned socks5_closed_on_read();
static unsigned socks5_closed_on_write();
static void socks5_request_on_arrival(const unsigned int state, struct selector_key * key);
static unsigned socks5_request_on_read(struct selector_key * key);
static void socks5_request_response_on_arrival(const unsigned int state, struct selector_key * key);
static unsigned socks5_request_response_on_read(struct selector_key * key);
static unsigned socks5_request_connect_on_write(struct selector_key * key);
static unsigned socks5_request_bind_on_write(struct selector_key * key);
static void * dns_resolve_thread(void * arg);
static int get_bound_address(int fd, socks5_address *addr);
static void socks5_request_resolver_on_arrival(const unsigned state, struct selector_key *key);
static unsigned socks5_request_resolver(struct selector_key * key);


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
    },
    [REQUEST_RESOLVER] = {
        .state = REQUEST_RESOLVER,
        .on_arrival = socks5_request_resolver_on_arrival,
        .on_read_ready = socks5_request_resolver,
        .on_block_ready = socks5_request_resolver,
    },
};

static void socks5_handshake_on_arrival(const unsigned int state, struct selector_key * key) {
    (void)state; 
    socks5_connection_t * connection = key->data;
    connection->parser.handshake.bytes_read = 0;
    connection->parser.handshake.bytes_written = 0;
    connection->parser.handshake.request.version = SOCKS5_VERSION;
    connection->parser.handshake.request.nmethods = 0;
    connection->parser.handshake.response.version = SOCKS5_VERSION;
    connection->parser.handshake.response.method    = HANDSHAKE_METHOD_NO_ACCEPTABLE;
}

static unsigned socks5_handshake_on_read(struct selector_key * key) {
    socks5_connection_t * connection = key->data;
    handshake_context_t * handshake = &connection->parser.handshake;
    buffer * b = &connection->read_c;
    
    size_t bytes;
    uint8_t * des = buffer_write_ptr(b, &bytes);
    ssize_t rec = recv(key->fd, des, bytes, 0);

    if(rec < 0){
        perror("recv");
        return ERROR;
    }
    else if (rec == 0){
        return CLOSED;
    }
    else{
        buffer_write_adv(b, (size_t)rec);
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

        if(handshake->bytes_read == (size_t)(2 + handshake->request.nmethods)){
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
                buffer_write(&connection->write_p, resp[i]);
            }
            selector_set_interest_key(key, OP_WRITE);
            return (handshake->response.method == HANDSHAKE_METHOD_NO_ACCEPTABLE) ? ERROR : HANDSHAKE_RESPONSE;
        }
    }

    return HANDSHAKE;
}

const struct socks5_state_definition * get_socks5_state_definition() {
    return (struct socks5_state_definition *)socks5_states_def;
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

static void socks5_authentication_on_arrival(const unsigned int state, struct selector_key * key) {
    (void)state; 
    socks5_connection_t * connection = key->data;
    authentication_context_t * auth_ctx = &connection->parser.authentication;
    auth_ctx->request.version = 0;
    auth_ctx->request.ulen = 0;
    auth_ctx->request.plen = 0;
    auth_ctx->response.version = AUTH_VERSION;
    auth_ctx->response.status = 0;
    auth_ctx->bytes_read = 0;
    auth_ctx->bytes_written = 0;
    auth_ctx->index = AUTH_STATE_VERSION;
}

static unsigned socks5_authentication_on_read(struct selector_key * key) {
    socks5_connection_t * connection = key->data;
    buffer * b = &connection->read_c;
    authentication_context_t * auth_ctx = &connection->parser.authentication;
    size_t bytes;
    uint8_t * des = buffer_write_ptr(b, &bytes);
    ssize_t rec = recv(key->fd, des, bytes, 0);
    if(rec == 0){
        return CLOSED;
    }
    else if(rec < 0){
        perror("recv error");
        return ERROR;
    }
    else{
        buffer_write_adv(b, (size_t)rec);
    }

    bool error = false;
    auth_index res = authentication_parse(&connection->parser.authentication, b, &error);
    if(error){
        selector_set_interest_key(key, OP_WRITE);
        return AUTHENTICATION_RESPONSE;
    }
    if(res == AUTH_COMPLETED){
        user_t * user = authenticate_user(auth_ctx->request.username, auth_ctx->request.password);
        connection->user = user;
        connection->auth_status = (user != NULL) ? AUTH_SUCCESS : AUTH_FAILED;
        buffer *wb = &connection->write_p;
        size_t available;
        uint8_t *out = buffer_write_ptr(wb, &available);
        if (available >= 2) {
            out[0] = auth_ctx->response.version;
            out[1] = auth_ctx->response.status;
            buffer_write_adv(wb, 2);
        } else {
            buffer_write(wb, auth_ctx->response.version);
            buffer_write(wb, auth_ctx->response.status);
        }
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

static unsigned socks5_error_on_read(){
    return CLOSED;
}

static unsigned socks5_error_on_write(){
    return CLOSED;
}

static unsigned socks5_closed_on_read(){
    return CLOSED;
}

static unsigned socks5_closed_on_write(){
    return CLOSED;
}

static void socks5_request_on_arrival(const unsigned int state, struct selector_key * key){
    (void)state; 
    selector_set_interest_key(key, OP_READ);
}

static void * dns_resolve_thread(void * arg){
    struct selector_key * key = (struct selector_key *)arg;
    socks5_connection_t * connection = key->data;

    uint16_t port = connection->parser.request.request.dest_address.port;
    char s[6];
    snprintf(s, sizeof(s), "%u", port);

    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM
    };

    int res = getaddrinfo((char*)connection->parser.request.request.dest_address.address.domainname.addr, s, &hints, &connection->req_address);

    if(res != 0){
        connection->req_address = NULL;
    }
    
    selector_notify_block(key->s, key->fd);
    free(arg);
    return NULL;
}

static unsigned socks5_request_on_read(struct selector_key * key){
    socks5_connection_t * connection = key->data;
    buffer * b = &connection->read_c;

    size_t bytes;
    uint8_t * des = buffer_write_ptr(b, &bytes);
    ssize_t rec = recv(key->fd, des, bytes, 0);
    if(rec == 0){
        return CLOSED;
    }
    else if(rec < 0){
        perror("recv");
        return ERROR;
    }
    else{
        buffer_write_adv(b, (size_t)rec);
    }

    size_t disp;
    uint8_t * buf = buffer_read_ptr(b, &disp);
    size_t ocu = 0;
    int res = parse_socks5_request(&connection->parser.request.request, buf, disp, &ocu);

    if(res == 0){
        buffer_read_adv(b, ocu);
        switch(connection->parser.request.request.command){
            case SOCKS5_COM_CONNECT:
                switch(connection->parser.request.request.dest_address.atyp){
                    case SOCKS5_ATYP_IPV4:
                        connection->remote_domain = AF_INET;
                        connection->remote_address_len = sizeof(struct sockaddr_in);
                        struct sockaddr_in * address_in4 = (struct sockaddr_in *)&connection->remote_address;

                        address_in4->sin_family = AF_INET;
                        memcpy(&address_in4->sin_addr, connection->parser.request.request.dest_address.address.ipv4, 4);
                        address_in4->sin_port = htons(connection->parser.request.request.dest_address.port);
                        
                        char ip4_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, connection->parser.request.request.dest_address.address.ipv4, ip4_str, INET_ADDRSTRLEN);
                        
                        //VER IMPELEMENTACION
                        int target_fd_new = socket(connection->remote_domain, SOCK_STREAM | SOCK_NONBLOCK, 0);
                        if(target_fd_new >= 0) {
                            int connect_result = connect(target_fd_new, (struct sockaddr*)&connection->remote_address, connection->remote_address_len);
                            if(connect_result == 0 || (connect_result == -1 && errno == EINPROGRESS)) {
                                connection->target_fd = target_fd_new;
                                selector_set_interest_key(key, OP_WRITE);
                                return REQUEST_CONNECT;
                            }
                            close(target_fd_new);
                        }
                        return ERROR;

                    case SOCKS5_ATYP_DOMAINNAME: {
                        struct selector_key *sk = malloc(sizeof(struct selector_key));
                        if(!sk) return ERROR;
                        *sk = *key;
                        pthread_t dns_thread;
                        if(pthread_create(&dns_thread, NULL, dns_resolve_thread, sk) != 0){
                            free(sk);
                            return ERROR;
                        }
                        pthread_detach(dns_thread);
                        selector_set_interest_key(key, OP_NOOP);
                        return REQUEST_CONNECT;
                    }

                    case SOCKS5_ATYP_IPV6:
                        connection->remote_domain = AF_INET6;
                        connection->remote_address_len = sizeof(struct sockaddr_in6);
                        struct sockaddr_in6 * address_in6 = (struct sockaddr_in6 *)&connection->remote_address;

                        address_in6->sin6_family = AF_INET6;
                        memcpy(&address_in6->sin6_addr, connection->parser.request.request.dest_address.address.ipv6, 16);
                        address_in6->sin6_port = htons(connection->parser.request.request.dest_address.port);

                        char ip6_str[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, connection->parser.request.request.dest_address.address.ipv6, ip6_str, INET6_ADDRSTRLEN);
                        
                        //VER IMPELEMENTACION
                        target_fd_new = socket(connection->remote_domain, SOCK_STREAM | SOCK_NONBLOCK, 0);
                        if(target_fd_new >= 0) {
                            int connect_result = connect(target_fd_new, (struct sockaddr*)&connection->remote_address, connection->remote_address_len);
                            if(connect_result == 0 || (connect_result == -1 && errno == EINPROGRESS)) {
                                connection->target_fd = target_fd_new;
                                selector_set_interest_key(key, OP_WRITE);
                                return REQUEST_CONNECT;
                            }
                            close(target_fd_new);
                        }
                        return ERROR;
                }
            case SOCKS5_COM_BIND:
                selector_set_interest_key(key, OP_WRITE);
                return REQUEST_BIND;
            default:
                return ERROR;
        }
    }
    return REQUEST;
}

static void socks5_request_response_on_arrival(const unsigned int state, struct selector_key * key){
    (void)state; 
    selector_set_interest_key(key, OP_READ);
}

static unsigned socks5_request_response_on_read(struct selector_key * key){
    socks5_connection_t * connection = key->data;

    if (connection->req_address == NULL) {
        return ERROR; 
    }
    struct addrinfo * resp = connection->req_address;
    struct addrinfo * cur = resp;
    
    while (cur != NULL) {
        connection->remote_domain = cur->ai_family;
        connection->remote_address_len = cur->ai_addrlen;
        memcpy(&connection->remote_address, cur->ai_addr, cur->ai_addrlen);

        int target_fd = socket(connection->remote_domain, SOCK_STREAM, 0);
        if (target_fd >= 0) {
            int connect_result = connect(target_fd, (struct sockaddr *)&connection->remote_address, connection->remote_address_len);
            if (connect_result == 0) {
                connection->target_fd = target_fd; 
                return REQUEST_CONNECT;
            }
            close(target_fd); 
        }

        cur = cur->ai_next;
    }

    freeaddrinfo(resp);
    connection->req_address = NULL;

    socks5_response_parser_t reply = {
        .version = SOCKS5_VERSION,
        .response = SOCKS5_REP_HOST_UNREACHABLE,
        .reserved = 0x00
    };
    

    reply.add.atyp = (connection->remote_domain == AF_INET) ? SOCKS5_ATYP_IPV4 : SOCKS5_ATYP_IPV6;
    if (reply.add.atyp == SOCKS5_ATYP_IPV4) {
        memset(reply.add.address.ipv4, 0, 4);
    } else {
        memset(reply.add.address.ipv6, 0, 16);
    }
    reply.add.port = 0;

    uint8_t * r;
    size_t len;
    if (socks5_response(&reply, &r, &len) < 0) {
        fprintf(stderr, "Error al generar la respuesta SOCKS5\n");
        return ERROR;
    }    
    for(size_t i = 0; i < len; i++){
        buffer_write(&connection->write_p, r[i]);
    }
    free(r);
    
    selector_set_interest_key(key, OP_WRITE);
    return CLOSED;
}

static int get_bound_address(int fd, socks5_address *addr) {
    struct sockaddr_storage s;
    socklen_t len = sizeof(s);

    if(getsockname(fd, (struct sockaddr *)&s, &len) < 0) {
        return -1;
    }

    if(s.ss_family == AF_INET) {
        struct sockaddr_in *addr_in4 = (struct sockaddr_in *)&s;
        addr->atyp = SOCKS5_ATYP_IPV4;
        memcpy(addr->address.ipv4, &addr_in4->sin_addr, 4);
        addr->port = addr_in4->sin_port; 
    }
    else if(s.ss_family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&s;
        addr->atyp = SOCKS5_ATYP_IPV6;
        memcpy(addr->address.ipv6, &addr_in6->sin6_addr, 16);
        addr->port = addr_in6->sin6_port; 
    }
    else {
        return -1;
    }
    return 0;
}

static unsigned socks5_request_connect_on_write(struct selector_key * key){
    socks5_connection_t * connection = key->data;
    int rfd = connection->target_fd;
    
    if(rfd == -1){
        return ERROR;
    }

    int err = 0; 
    socklen_t len = sizeof(err);
    if(getsockopt(rfd, SOL_SOCKET, SO_ERROR, &err, &len) < 0){
        return ERROR;
    }
    
    if(err){
        return ERROR;
    }

    socks5_response_parser_t reply = {
        .version = SOCKS5_VERSION,
        .response = SOCKS5_REP_SUCCEEDED,
        .reserved = 0x00
    };
    
    if(get_bound_address(rfd, &reply.add) < 0) {
        return ERROR;
    }

    uint8_t *out; 
    size_t outlen;
    socks5_response(&reply, &out, &outlen);
    for(size_t i = 0; i < outlen; i++){
        buffer_write(&connection->write_p, out[i]);
    }
    free(out);

    connection->stm.current = &connection->stm.states[REQUEST_RESPONSE];
    selector_set_interest(key->s, connection->client_fd, OP_WRITE);
    selector_set_interest(key->s, connection->target_fd, OP_READ);
    return REQUEST_RESPONSE;
}


static unsigned socks5_request_bind_on_write(struct selector_key * key){
    socks5_connection_t * connection = key->data;
    socks5_response_parser_t reply = {
        .version = SOCKS5_VERSION,
        .response = SOCKS5_REP_SUCCEEDED,
        .reserved = 0x00,
        .add = {.atyp = SOCKS5_ATYP_IPV4}
    };

    if(get_bound_address(connection->target_fd, &reply.add) < 0) {
        return ERROR;
    }

    uint8_t * r;
    size_t len;
    if (socks5_response(&reply, &r, &len) < 0) {
        fprintf(stderr, "Error al generar la respuesta SOCKS5\n");
        return ERROR;
    }

    for(size_t i = 0; i < len; i++){
        buffer_write(&connection->write_p, r[i]);
    }
    free(r);

    selector_set_interest_key(key, OP_WRITE);
    return REQUEST_RESPONSE;
}

static unsigned socks5_request_resolver(struct selector_key * key) {
    socks5_connection_t * connection = key->data;
    if (connection->req_address == NULL) {
        return ERROR;
    }

    struct addrinfo * resp = connection->req_address;
    struct addrinfo * cur = resp;

    while (cur != NULL) {
        connection->remote_domain = cur->ai_family;
        connection->remote_address_len = cur->ai_addrlen;
        memcpy(&connection->remote_address, cur->ai_addr, cur->ai_addrlen);

        int target_fd = socket(connection->remote_domain, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (target_fd >= 0) {
            int connect_result = connect(target_fd, (struct sockaddr *)&connection->remote_address, connection->remote_address_len);
            if (connect_result == 0 || (connect_result == -1 && errno == EINPROGRESS)) {
                connection->target_fd = target_fd;
                freeaddrinfo(resp);
                connection->req_address = NULL;
                selector_set_interest_key(key, OP_WRITE);
                return REQUEST_CONNECT;
            }
            close(target_fd);
        }
        cur = cur->ai_next;
    }

    freeaddrinfo(resp);
    connection->req_address = NULL;

    socks5_response_parser_t reply = {
        .version = SOCKS5_VERSION,
        .response = SOCKS5_REP_HOST_UNREACHABLE,
        .reserved = 0x00
    };

    reply.add.atyp = (connection->remote_domain == AF_INET) ? SOCKS5_ATYP_IPV4 : SOCKS5_ATYP_IPV6;
    if (reply.add.atyp == SOCKS5_ATYP_IPV4) {
        memset(reply.add.address.ipv4, 0, 4);
    } else {
        memset(reply.add.address.ipv6, 0, 16);
    }
    reply.add.port = 0;

    uint8_t * r;
    size_t len;
    if (socks5_response(&reply, &r, &len) < 0) {
        fprintf(stderr, "Error al generar la respuesta SOCKS5\n");
        return ERROR;
    }
    for(size_t i = 0; i < len; i++){
        buffer_write(&connection->write_p, r[i]);
    }
    free(r);

    selector_set_interest_key(key, OP_WRITE);
    return CLOSED;
}

static void socks5_request_resolver_on_arrival(const unsigned state, struct selector_key *key){
    (void)state;
    selector_set_interest_key(key, OP_READ);
}