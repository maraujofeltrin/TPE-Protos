#ifndef METP_H_
#define METP_H_

#include "selector.h"
#include "../../utils/include/stm.h"

typedef enum {
    METP_AUTH,
    METP_COMMAND,
    METP_RESPONSE,
    METP_CLOSED,
    METP_ERROR,
} metp_state_t;

void metp_read(struct selector_key *key);
void metp_write(struct selector_key *key);
void metp_block(struct selector_key *key);


#endif