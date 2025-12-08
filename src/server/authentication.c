#include "include/authentication.h"
#include "buffer.h"

auth_index authentication_parse(struct authentication_context * auth_ctx, buffer * buff, bool * error) {
    while(buffer_can_read(buff)) {
        uint8_t aux = buffer_read(buff);
        switch(auth_ctx->index) {
            case AUTH_STATE_VERSION:
                auth_ctx->request.version = aux;
                if(auth_ctx->request.version != AUTH_VERSION) {
                    auth_ctx->response.status = AUTH_ERROR_VERSION;
                    auth_ctx->index = AUTH_FAILED;
                    *error = true;
                    return AUTH_FAILED;
                }
                auth_ctx->index = AUTH_STATE_ULEN;
                break;
            case AUTH_STATE_ULEN:
                auth_ctx->request.ulen = aux;
                auth_ctx->bytes_read = 0;
                if(auth_ctx->request.ulen == 0) {
                    auth_ctx->index = AUTH_STATE_PLEN;
                } else {
                    auth_ctx->index = AUTH_STATE_UNAME;
                }
                break;
            case AUTH_STATE_UNAME:
                auth_ctx->request.username[auth_ctx->bytes_read++] = aux;
                if(auth_ctx->bytes_read == auth_ctx->request.ulen) {
                    auth_ctx->request.username[auth_ctx->request.ulen] = '\0';
                    auth_ctx->bytes_read = 0;
                    auth_ctx->index = AUTH_STATE_PLEN;
                }
                break;
            case AUTH_STATE_PLEN:
                auth_ctx->request.plen = aux;
                auth_ctx->bytes_read = 0;
                if(auth_ctx->request.plen == 0) {
                    auth_ctx->index = AUTH_COMPLETED;
                    auth_ctx->request.password[0] = '\0';
                    return AUTH_COMPLETED;
                }
                auth_ctx->index = AUTH_STATE_PASSWD;
                break;
            case AUTH_STATE_PASSWD:
                auth_ctx->request.password[auth_ctx->bytes_read++] = aux;
                if(auth_ctx->bytes_read == auth_ctx->request.plen) {
                    auth_ctx->request.password[auth_ctx->request.plen] = '\0';
                    auth_ctx->index = AUTH_COMPLETED;
                    return AUTH_COMPLETED;
                }
                break;
            case AUTH_ERROR_DEFAULT:
                return auth_ctx->index;
            case AUTH_ERROR_VERSION:
                return auth_ctx->index;
            case AUTH_COMPLETED:
                return auth_ctx->index;
            default:
                auth_ctx->response.status = AUTH_ERROR_DEFAULT;
                auth_ctx->index = AUTH_FAILED;
                *error = true;
                return AUTH_FAILED;
        }
    }
    return auth_ctx->index;
}