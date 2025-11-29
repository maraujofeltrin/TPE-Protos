#ifndef S5MP_H_
#define S5MP_H_

#include "selector.h"
#include "../../utils/include/stm.h"
#include "../../utils/include/buffer.h"


#define USER_MAX 32
#define BUFFER_MAX 4096

typedef enum {
    S5MP_HANDSHAKE,
    S5MP_HANDSHAKE_RESPONSE,
    S5MP_AUTH,
    S5MP_REQUEST,
    S5MP_REQUEST_RESPONSE,
    S5MP_ERROR,
    S5MP_AUTH_RESPONSE,
    S5MP_TERMINATED
} s5mp_state_t;

typedef struct s5mp_parser{
    char text[BUFFER_MAX];
    size_t cantBytes;
}s5mp_parser;

typedef struct s5mp_connection {
    int fd_client;
    bool authenticated;
    bool conected;
    bool close;
    bool valid;
    
    struct state_machine stm;

    char cur_user[USER_MAX];

    union{
        s5mp_parser auth_parser;
        s5mp_parser request_parser;
    }parser;

    char * to_send;
    size_t to_send_remaining;
    bool sending;
    
    buffer * buffer_r;
    buffer * buffer_w;
}s5mp_connection_t;

const struct state_definition * get_s5mp_state_definition(void);
size_t get_s5mp_buffer_size();

#endif