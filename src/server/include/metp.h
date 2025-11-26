#ifndef METP_H_
#define METP_H_

#include "selector.h"
#include "../../utils/include/stm.h"
#include "../../utils/include/buffer.h"


#define USER_MAX 32
#define BUFFER_MAX 512

typedef enum {
    METP_HANDSHAKE,
    METP_HANDSHAKE_RESPONSE,
    METP_AUTH,
    METP_REQUEST,
    METP_REQUEST_RESPONSE,
    METP_ERROR,
    METP_AUTH_RESPONSE,
    METP_TERMINATED
} metp_state_t;

void metp_read(struct selector_key *key);
void metp_write(struct selector_key *key);
void metp_block(struct selector_key *key);

typedef struct metp_connection {
    int fd_client;
    bool authenticated;
    bool conected;
    bool close;
    
    struct state_machine stm;

    char cur_user[USER_MAX];

    union{
        metp_parser auth_parser;
        metp_parser command_parser;
    }parser;

    char * to_send;
    size_t to_send_remaining;
    bool sending;
    
    buffer * buffer_r;
    buffer * buffer_w;
}metp_connection_t;

typedef struct metp_parser{
    char text[BUFFER_MAX];
    size_t cantBytes
}metp_parser;


#endif