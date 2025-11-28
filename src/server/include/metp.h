#ifndef METP_H_
#define METP_H_

#include "selector.h"
#include "../../utils/include/stm.h"
#include "../../utils/include/buffer.h"


#define USER_MAX 32
#define BUFFER_MAX 4096

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

typedef struct metp_parser{
    char text[BUFFER_MAX];
    size_t cantBytes;
}metp_parser;

typedef struct metp_connection {
    int fd_client;
    bool authenticated;
    bool conected;
    bool close;
    bool valid;
    
    struct state_machine stm;

    char cur_user[USER_MAX];

    union{
        metp_parser auth_parser;
        metp_parser request_parser;
    }parser;

    char * to_send;
    size_t to_send_remaining;
    bool sending;
    
    buffer * buffer_r;
    buffer * buffer_w;
}metp_connection_t;

const struct state_definition * get_metp_state_definition(void);
size_t get_metp_buffer_size();

#endif