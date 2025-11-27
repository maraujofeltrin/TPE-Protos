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

#include "../utils/include/selector.h"
#include "../utils/include/buffer.h"

#define ECHO_BUF_SIZE 8192

struct echo_connection {
    int fd;
    buffer in;
    buffer out;
    uint8_t *in_data;
    uint8_t *out_data;
};

static void client_handle_close(struct selector_key *key);
static void client_handle_read(struct selector_key *key);
static void client_handle_write(struct selector_key *key);
static void listener_handle_read(struct selector_key *key);

static const struct fd_handler client_handler = {
    .handle_read = client_handle_read,
    .handle_write = client_handle_write,
    .handle_block = NULL,
    .handle_close = client_handle_close,
};

static const struct fd_handler listener_handler = {
    .handle_read = listener_handle_read,
    .handle_write = NULL,
    .handle_block = NULL,
    .handle_close = NULL,
};

static int set_nonblocking(int fd) {
    return selector_fd_set_nio(fd);
}

static void client_handle_close(struct selector_key *key) {
    struct echo_connection *c = key->data;
    if(!c) return;
    selector_unregister_fd(key->s, c->fd);
    close(c->fd);
    free(c->in_data);
    free(c->out_data);
    free(c);
}

static void client_handle_read(struct selector_key *key) {
    struct echo_connection *c = key->data;
    if(!c) return;

    size_t w_avail;
    uint8_t *wptr = buffer_write_ptr(&c->in, &w_avail);
    ssize_t rec = recv(c->fd, wptr, w_avail, 0);
    if(rec == 0) {
        client_handle_close(key);
        return;
    }
    if(rec < 0) {
        if(errno == EAGAIN || errno == EWOULDBLOCK) return;
        client_handle_close(key);
        return;
    }
    buffer_write_adv(&c->in, rec);

    while(buffer_can_read(&c->in) && buffer_can_write(&c->out)) {
        size_t r_avail, w_avail2;
        uint8_t *rptr = buffer_read_ptr(&c->in, &r_avail);
        uint8_t *wptr2 = buffer_write_ptr(&c->out, &w_avail2);
        size_t tocopy = r_avail < w_avail2 ? r_avail : w_avail2;
        memcpy(wptr2, rptr, tocopy);
        buffer_read_adv(&c->in, tocopy);
        buffer_write_adv(&c->out, tocopy);
    }

    selector_set_interest_key(key, OP_WRITE);
}

static void client_handle_write(struct selector_key *key) {
    struct echo_connection *c = key->data;
    if(!c) return;

    if(!buffer_can_read(&c->out)) {
        selector_set_interest_key(key, OP_READ);
        return;
    }

    size_t r_avail;
    uint8_t *rptr = buffer_read_ptr(&c->out, &r_avail);
    ssize_t sent = send(c->fd, rptr, r_avail, MSG_NOSIGNAL);
    if(sent < 0) {
        if(errno == EAGAIN || errno == EWOULDBLOCK) return;
        client_handle_close(key);
        return;
    }
    buffer_read_adv(&c->out, sent);

    if(!buffer_can_read(&c->out)) {
        selector_set_interest_key(key, OP_READ);
    }
}

static void listener_handle_read(struct selector_key *key) {
    int listen_fd = key->fd;
    for(;;) {
        struct sockaddr_storage addr;
        socklen_t addrlen = sizeof(addr);
        int client = accept(listen_fd, (struct sockaddr*)&addr, &addrlen);
        if(client < 0) {
            if(errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            perror("accept");
            break;
        }

        if(set_nonblocking(client) < 0) {
            perror("set_nonblocking");
            close(client);
            continue;
        }

        struct echo_connection *c = calloc(1, sizeof(*c));
        if(!c) { close(client); continue; }
        c->fd = client;
        c->in_data = malloc(ECHO_BUF_SIZE);
        c->out_data = malloc(ECHO_BUF_SIZE);
        if(!c->in_data || !c->out_data) {
            close(client);
            free(c->in_data);
            free(c->out_data);
            free(c);
            continue;
        }
        buffer_init(&c->in, ECHO_BUF_SIZE, c->in_data);
        buffer_init(&c->out, ECHO_BUF_SIZE, c->out_data);

        selector_status st = selector_register(key->s, client, &client_handler, OP_READ, c);
        if(st != SELECTOR_SUCCESS) {
            fprintf(stderr, "selector_register failed: %s\n", selector_error(st));
            close(client);
            free(c->in_data);
            free(c->out_data);
            free(c);
            continue;
        }
        fprintf(stderr, "accepted client fd=%d\n", client);
    }
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;

    struct selector_init sconf = {
        .signal = SIGUSR1,
        .select_timeout = { .tv_sec = 5, .tv_nsec = 0 }
    };

    if(selector_init(&sconf) != SELECTOR_SUCCESS) {
        fprintf(stderr, "selector_init failed\n");
        return EXIT_FAILURE;
    }

    fd_selector sel = selector_new(32);
    if(!sel) {
        fprintf(stderr, "selector_new failed\n");
        return EXIT_FAILURE;
    }

    int port = 1080;
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(listen_fd < 0) { perror("socket"); return EXIT_FAILURE; }
    int on = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if(bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); close(listen_fd); return EXIT_FAILURE; }
    if(listen(listen_fd, 128) < 0) { perror("listen"); close(listen_fd); return EXIT_FAILURE; }
    if(set_nonblocking(listen_fd) < 0) { perror("set_nonblocking"); close(listen_fd); return EXIT_FAILURE; }

    if(selector_register(sel, listen_fd, &listener_handler, OP_READ, NULL) != SELECTOR_SUCCESS) {
        fprintf(stderr, "failed to register listener\n");
        close(listen_fd);
        selector_destroy(sel);
        return EXIT_FAILURE;
    }

    fprintf(stderr, "echoserver listening on port %d\n", port);

    while(1) {
        selector_status st = selector_select(sel);
        if(st != SELECTOR_SUCCESS) {
            if(st == SELECTOR_IO) {
                perror("selector_select");
            }
        }
    }

    selector_destroy(sel);
    close(listen_fd);
    return EXIT_SUCCESS;
}