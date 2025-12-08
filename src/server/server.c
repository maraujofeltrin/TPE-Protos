#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <netdb.h>
#include <sys/types.h>

#include "../utils/include/selector.h"
#include "../utils/include/buffer.h"
#include "include/socks5.h"
#include "include/s5mp.h"
#include "include/users.h"
#include "include/metrics.h"
#include "../utils/include/args.h"


static void socks5_handle_read(struct selector_key *key);
static void socks5_handle_write(struct selector_key *key);
static void socks5_handle_close(struct selector_key *key);
static void socks5_handle_block(struct selector_key *key);
static void socks5_handle_accept_connection(struct selector_key *key);


// S5MP handlers
static void s5mp_handle_read(struct selector_key *key);
static void s5mp_handle_write(struct selector_key *key);
static void s5mp_handle_close(struct selector_key *key);
static void s5mp_handle_block(struct selector_key *key);
static void s5mp_handle_accept_connection(int server_fd, fd_selector selector);

// Listeners
static int create_listeners(const char *addr, const char *port);
static void s5mp_accept_wrapper(struct selector_key *key);

static const struct fd_handler socks5_handler = {
    .handle_read = socks5_handle_read,
    .handle_write = socks5_handle_write,
    .handle_block = socks5_handle_block,
    .handle_close = socks5_handle_close,
};

int register_socks5_target_fd(fd_selector s, int fd, void *data) {
    return selector_register(s, fd, &socks5_handler, OP_NOOP, data);
}

static const struct fd_handler s5mp_handler = {
    .handle_read = s5mp_handle_read,
    .handle_write = s5mp_handle_write,
    .handle_block = s5mp_handle_block,
    .handle_close = s5mp_handle_close,
};


// SOCKS5 handlers
static void socks5_handle_write(struct selector_key *key){
    socks5_connection_t * connection = (socks5_connection_t *) key->data;
    if(connection == NULL){
        return;
    }

    unsigned next = stm_handler_write(&connection->stm, key);
    
    if(next == CLOSED){
        socks5_handle_close(key);
        return;
    }
    
    if (key->data) {
        connection = (socks5_connection_t *) key->data;
        connection->stm.current = &connection->stm.states[next];
    }
}

static void socks5_handle_close(struct selector_key *key){
    if (key == NULL || key->data == NULL){
        return;
    }

    socks5_connection_t * connection = (socks5_connection_t *) key->data;
    if(connection == NULL){
        return;
    }


    if (connection->tobe_closed) {
        return;
    }
    connection->tobe_closed = true;

    if (connection->client_fd >= 0) {
        selector_unregister_fd(key->s, connection->client_fd);
    }
    if (connection->target_fd >= 0 && connection->target_fd != connection->client_fd) {
        selector_unregister_fd(key->s, connection->target_fd);
    }

    stm_handler_close(&connection->stm, key);

    if(connection->target_fd >= 0){
        close(connection->target_fd);
        connection->target_fd = -1;
    }
    if(connection->client_fd >= 0){
        close(connection->client_fd);
        connection->client_fd = -1;
    }

    // Register access log if user authenticated and bytes transferred
    if (connection->user != NULL && connection->bytes_sent > 0) {
        const char *username = connection->user->username ? connection->user->username : "unknown";
        const char *client_ip = connection->client_ip[0] != '\0' ? connection->client_ip : "unknown";
        const char *dest = connection->target_addr[0] != '\0' ? connection->target_addr : "unknown";
        access_logs(username, client_ip, dest, connection->bytes_sent);
    }

    metrics_connection_closed();
    free(connection);
    key->data = NULL;  
}

static void socks5_handle_block(struct selector_key *key){
    socks5_connection_t * connection = (socks5_connection_t *) key->data;
    if (!connection) return;

    unsigned int next = stm_handler_block(&connection->stm, key);

    if (!key->data) return;
    connection = (socks5_connection_t *) key->data;
    connection->stm.current = &connection->stm.states[next]; 
}



// S5MP handlers
static void s5mp_handle_read(struct selector_key *key){
    s5mp_connection_t * connection = (s5mp_connection_t *) key->data;
    if(connection == NULL || !connection->valid){
        return;
    }
    unsigned next =  stm_handler_read(&connection->stm, key);

    if (!key->data) return;
    connection = (s5mp_connection_t *) key->data;
    connection->stm.current = &connection->stm.states[next];
}

static void s5mp_handle_write(struct selector_key *key){
    s5mp_connection_t * connection = (s5mp_connection_t *) key->data;
    if(connection == NULL){
        return;
    }

    unsigned next =  stm_handler_write(&connection->stm, key);
    if(next == S5MP_TERMINATED){
        selector_unregister_fd(key->s, key->fd);
        return;
    }
    if (!key->data) return;
    connection = (s5mp_connection_t *) key->data;
    connection->stm.current = &connection->stm.states[next];
    
    if (next == S5MP_REQUEST && buffer_can_read(connection->buffer_r)) {
        stm_handler_read(&connection->stm, key);
    }
}

static void s5mp_handle_close(struct selector_key *key){
    s5mp_connection_t * connection = (s5mp_connection_t *) key->data;
    if(connection == NULL){
        return;
    }    
    connection->valid = false;
    
    close(key->fd);
    
    free(connection->buffer_r);
    free(connection->buffer_w);
    free(connection); 
}

static void s5mp_handle_block(struct selector_key *key){
    s5mp_connection_t * connection = (s5mp_connection_t *) key->data;
    if (!connection) return;

    unsigned int next = stm_handler_block(&connection->stm, key);
    if (!key->data) return;
    connection = (s5mp_connection_t *) key->data;
    connection->stm.current = &connection->stm.states[next];
}

static void s5mp_handle_accept_connection(int server_fd, fd_selector selector){
    int client_fd = accept(server_fd, NULL, NULL);
    if(client_fd < 0) {
        perror("Failed to accept S5MP connection");
        return;
    }
    if(fcntl(client_fd, F_SETFL, O_NONBLOCK) < 0) {
        perror("Failed to set non-blocking mode");
        close(client_fd);
        return;
    }
    s5mp_connection_t *connection = calloc(1, sizeof(s5mp_connection_t));
    if(!connection) {
        fprintf(stderr, "Failed to initialize S5MP connection\n");
        close(client_fd);
        return;
    }
    
    connection->fd_client = client_fd;
    connection->authenticated = false;
    connection->conected = false;
    connection->close = false;
    connection->valid = true;
    
    connection->buffer_r = malloc(sizeof(buffer));
    connection->buffer_w = malloc(sizeof(buffer));
    uint8_t *raw_r = malloc(BUFFER_MAX);
    uint8_t *raw_w = malloc(BUFFER_MAX);
    
    if(!connection->buffer_r || !connection->buffer_w || !raw_r || !raw_w){
        free(connection->buffer_r);
        free(connection->buffer_w);
        free(raw_r);
        free(raw_w);
        free(connection);
        return;
    }
    
    buffer_init(connection->buffer_r, BUFFER_MAX, raw_r);
    buffer_init(connection->buffer_w, BUFFER_MAX, raw_w);

    connection->stm.states = get_s5mp_state_definition();
    connection->stm.initial = S5MP_HANDSHAKE;
    connection->stm.max_state = S5MP_TERMINATED;

    stm_init(&connection->stm);

    if(selector_register(selector, client_fd, &s5mp_handler, OP_READ, connection) != SELECTOR_SUCCESS) {
        fprintf(stderr, "Failed to register S5MP client\n");
        close(client_fd);
        free(connection->buffer_r);
        free(connection->buffer_w);
        free(connection);   
        return;
    }

    if(connection->stm.states[S5MP_HANDSHAKE].on_arrival) {
        connection->stm.states[S5MP_HANDSHAKE].on_arrival(S5MP_HANDSHAKE, &(struct selector_key){.fd = client_fd, .data = connection });
    }
}


// Listeners
static int create_listeners(const char *addr, const char *port) {
    if (!addr || !port) {
        fprintf(stderr, "Invalid address or port\n");
        return -1;
    }
    
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_PASSIVE,
    }, *res;

    int status = getaddrinfo(addr, port, &hints, &res);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(status));
        return -1;
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd == -1) {
        perror("Failed to create socket");
        freeaddrinfo(res);
        return -1;
    }
    
    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("Failed to set SO_REUSEADDR");
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    
    if (bind(fd, res->ai_addr, res->ai_addrlen) == -1) {
        perror("Failed to bind socket");
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    
    if (listen(fd, SOMAXCONN) == -1) {
        perror("Failed to listen on socket");
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    
    freeaddrinfo(res);
    return fd;
}

static void s5mp_accept_wrapper(struct selector_key *key) {
    s5mp_handle_accept_connection(key->fd, key->s);
}



static void socks5_handle_read(struct selector_key *key){
    socks5_connection_t *conn = (socks5_connection_t *) key->data;
    if (!conn) return;
    
    if (conn->client_fd < 0 || (key->fd != conn->client_fd && key->fd != conn->target_fd)) {
        socks5_handle_close(key);
        return;
    }
    
    int next_state_socks5 = stm_handler_read(&conn->stm, key);

    
    if (!key->data) return;

    if(next_state_socks5 == CLOSED){
        socks5_handle_close(key);
        return;
    }

    conn = (socks5_connection_t *) key->data;
    conn->stm.current = &conn->stm.states[next_state_socks5];
}

static void socks5_handle_accept_connection(struct selector_key *key){
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    int client_fd = accept(key->fd, (struct sockaddr *)&addr, &addrlen);
    if(client_fd < 0) {
        perror("Failed to accept connection");
        return;
    }
    if(fcntl(client_fd, F_SETFL, O_NONBLOCK) < 0) {
        perror("Failed to set non-blocking mode");
        close(client_fd);
        return;
    }
    socks5_connection_t *connection = calloc(1, sizeof(socks5_connection_t));
    if(!connection) {
        fprintf(stderr, "Failed to initialize SOCKS5 connection\n");
        close(client_fd);
        return;
    }
    connection->client_fd = client_fd;
    connection->tobe_closed = false;
    connection->relay_active = false;
    connection->target_fd = -1;
    connection->stm.states = (const struct state_definition *)get_socks5_state_definition();
    connection->stm.max_state = REQUEST_RESOLVER;
    connection->stm.initial = HANDSHAKE;
    stm_init(&connection->stm);

    if(addr.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&addr;
        inet_ntop(AF_INET, &s->sin_addr, connection->client_ip, INET_ADDRSTRLEN);
    } else if(addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
        inet_ntop(AF_INET6, &s->sin6_addr, connection->client_ip, INET6_ADDRSTRLEN);
    }
    connection->bytes_sent = 0;
    size_t size = get_s5mp_buffer_size();
    buffer_init(&connection->read_c, size, connection->raw_read_c);
    buffer_init(&connection->write_c, size, connection->raw_write_c);
    buffer_init(&connection->read_p, size, connection->raw_read_p);
    buffer_init(&connection->write_p, size, connection->raw_write_p);
    
    if(selector_register(key->s, client_fd, &socks5_handler, OP_READ, connection) != SELECTOR_SUCCESS) {
        fprintf(stderr, "Failed to register SOCKS5 client\n");
        close(client_fd);
        free(connection);
        return;
    }
    metrics_connection_opened();
}



int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN); 
    printf("Starting SOCKS5 server...\n");
    struct socks5args args;
    parse_args(argc, argv, &args);

    metrics_init();
    users_init();


    for (int i = 0; args.users[i].name != NULL && i < MAX_USERS; i++) {
        user_role_t role = (i == 0) ? ROLE_ADMIN : ROLE_USER;
        users_add(args.users[i].name, args.users[i].pass, role);
    }

    selector_init(&(struct selector_init){
        .signal = SIGALRM,
        .select_timeout.tv_sec = 10,
        .select_timeout.tv_nsec = 0
    });

    fd_selector sel = selector_new(1024);
    if (sel == NULL) {
        perror("Failed to create selector");
        return 1;
    }

    char socks_port_str[6], mng_port_str[6];

    if (snprintf(socks_port_str, sizeof(socks_port_str), "%u", args.socks_port) >= (int)sizeof(socks_port_str) ||
        snprintf(mng_port_str, sizeof(mng_port_str), "%u", args.mng_port) >= (int)sizeof(mng_port_str)) {
        fprintf(stderr, "Port string truncated.\n");
        return 1;
    }

    int s5_fd = create_listeners(args.socks_addr, socks_port_str);
    if (s5_fd == -1) {
        fprintf(stderr, "Failed to create SOCKS5 listener on %s:%s\n", args.socks_addr, socks_port_str);
        selector_destroy(sel);
        return 1;
    }
    
    if (fcntl(s5_fd, F_SETFL, O_NONBLOCK) == -1) {
        perror("Failed to set SOCKS5 listener non-blocking");
        close(s5_fd);
        selector_destroy(sel);
        return 1;
    }
    
    static const struct fd_handler socks5_accept_handler = {
        .handle_read = socks5_handle_accept_connection,
        .handle_write = NULL,
        .handle_block = NULL,
        .handle_close = NULL,
    };
    
    if (selector_register(sel, s5_fd, &socks5_accept_handler, OP_READ, NULL) != SELECTOR_SUCCESS) {
        perror("Failed to register SOCKS5 listener");
        close(s5_fd);
        selector_destroy(sel);
        return 1;
    }

    int m_fd = create_listeners(args.mng_addr, mng_port_str);
    if (m_fd == -1) {
        fprintf(stderr, "Failed to create S5MP listener on %s:%s\n", args.mng_addr, mng_port_str);
        close(s5_fd);
        selector_destroy(sel);
        return 1;
    }
    
    if (fcntl(m_fd, F_SETFL, O_NONBLOCK) == -1) {
        perror("Failed to set S5MP listener non-blocking");
        close(s5_fd);
        close(m_fd);
        selector_destroy(sel);
        return 1;
    }
    
    static const struct fd_handler s5mp_accept_handler = {
        .handle_read = s5mp_accept_wrapper,
        .handle_write = NULL,
        .handle_block = NULL,
        .handle_close = NULL,
    };
    
    if (selector_register(sel, m_fd, &s5mp_accept_handler, OP_READ, NULL) != SELECTOR_SUCCESS) {
        perror("Failed to register S5MP listener");
        close(s5_fd);
        close(m_fd);
        selector_destroy(sel);
        return 1;
    }

    printf("SOCKS5 listening on %s:%u\n", args.socks_addr, args.socks_port);
    printf("Management listening on %s:%u\n", args.mng_addr, args.mng_port);

    while (1) {
        selector_select(sel);
    }

    selector_destroy(sel);
    close(s5_fd);
    close(m_fd);
    free_users();
    return 0;
}
