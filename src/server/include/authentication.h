#ifndef AUTHENTICATION_H
#define AUTHENTICATION_H
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "buffer.h"
#define AUTH_VERSION 0x01

static const uint8_t AUTH_FAILED = 0x00;
static const uint8_t AUTH_SUCCESS = 0x01;


typedef enum auth_index{
    AUTH_STATE_VERSION,
    AUTH_STATE_ULEN,
    AUTH_STATE_UNAME,
    AUTH_STATE_PLEN,
    AUTH_STATE_PASSWD,
    AUTH_ERROR_VERSION,
    AUTH_COMPLETED,
    AUTH_ERROR_DEFAULT
}auth_index;



typedef struct authentication_request {
    uint8_t version;
    uint8_t ulen;
    char username[255];
    uint8_t plen;
    char password[255];
    size_t bytes_read;
    size_t bytes_written;
} authentication_request_t;

typedef struct authentication_response {
    uint8_t version;
    uint8_t status;
} authentication_response_t;

typedef struct authentication_context {
    authentication_request_t request;
    authentication_response_t response;
    size_t bytes_read;
    size_t bytes_written;
    auth_index index;
} authentication_context_t;

auth_index authentication_parse(struct authentication_context * auth_ctx, buffer * buff, bool * error);
#endif