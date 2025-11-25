#ifndef METP_H_
#define METP_H_

#include "selector.h"
#include "../../utils/include/stm.h"

#define USER_MAX 32
#define BUFFER_MAX 512  //VER VALORES

typedef enum {
    METP_HANDSHAKE,
    METP_HANDSHAKE_RESPONSE,
    METP_AUTH,
    METP_COMMAND,
    METP_RESPONSE,
    METP_CLOSED,
    METP_ERROR,
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
    
    buffer * buffer_c;
    buffer * buffer_s;

}metp_connection_t;

typedef struct metp_parser{
    char text[BUFFER_MAX];
    size_t cantBytes
}metp_parser;


#endif