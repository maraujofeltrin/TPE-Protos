#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "selector.h"
#include "include/metp.h"

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
        .on_read_ready = metp_read,
        .on_write_ready = metp_write,
        .on_block_ready = metp_block,
    },
    [METP_COMMAND] = {
        .state = METP_COMMAND,
        .on_read_ready = metp_read,
        .on_write_ready = metp_write,
        .on_block_ready = metp_block,
    },
    [METP_RESPONSE] = {
        .state = METP_RESPONSE,
        .on_read_ready = metp_read,
        .on_write_ready = metp_write,
        .on_block_ready = metp_block,
    },
    [METP_CLOSED] = {
        .state = METP_CLOSED,
    },
    [METP_ERROR] = {
        .state = METP_ERROR,
    }
};

const struct state_definition * get_metp_state_definition() {
    return metp_states_def;
}

static unsigned metp_handshake_read(struct selector_key *key) {
    
}

static unsigned metp_handshake_response_write(struct selector_key *key) {
    
}

