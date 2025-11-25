#include "include/builder.h"
#include "include/socks5.h"
#include "include/authentication.h"
#include <string.h>

int parse_socks5_request(socks5_request_parser_t * request, const uint8_t * buf, size_t len, size_t * parsed_bytes) {
    if(len < 4) {
        return -1;
    }
    size_t offset = 0;
    request->version = buf[offset++];
    request->command = buf[offset++];
    request->reserved = buf[offset++];
    request->dest_address.atyp = buf[offset++];
    if(request->version != SOCKS5_VERSION) {
        return -1; // Invalid version
    }
    if(request->reserved != 0x00) {
        return -1; // Invalid reserved byte
    }
    switch(request->dest_address.atyp) {
        case SOCKS5_ATYP_IPV4:
            if(len < offset + 4 + 2) {
                return -1; // Not enough data
            }
            memcpy(request->dest_address.address.ipv4, &buf[offset], 4);
            offset += 4;
            /* read port (2 bytes) */
            request->dest_address.port = (buf[offset] << 8) | buf[offset + 1];
            offset += 2;
            break;
        case SOCKS5_ATYP_DOMAINNAME:
            if(len < offset + 1) {
                return -1;
            }
            request->dest_address.address.domainname.length = buf[offset++];
            if(len < offset + request->dest_address.address.domainname.length + 2) {
                return -1;
            }
            memcpy(request->dest_address.address.domainname.addr, &buf[offset], request->dest_address.address.domainname.length);
            offset += request->dest_address.address.domainname.length;
            /* read port (2 bytes) */
            request->dest_address.port = (buf[offset] << 8) | buf[offset + 1];
            offset += 2;
            break;
        case SOCKS5_ATYP_IPV6:
            if(len < offset + 16 + 2) {
                return -1;
            }
            memcpy(request->dest_address.address.ipv6, &buf[offset], 16);
            offset += 16;
            /* read port (2 bytes) */
            request->dest_address.port = (buf[offset] << 8) | buf[offset + 1];
            offset += 2;
            break;
        default:
            return -1;
    }

    *parsed_bytes = offset;
    return 0;
}

int socks5_response(socks5_response_parser_t * response, uint8_t ** out_buf, size_t * out_len) {
    size_t addr_len = 0;
    switch(response->add.atyp) {
        case SOCKS5_ATYP_IPV4:
            addr_len = 4;
            break;
        case SOCKS5_ATYP_DOMAINNAME:
            addr_len = 1 + response->add.address.domainname.length;
            break;
        case SOCKS5_ATYP_IPV6:
            addr_len = 16;
            break;
        default:
            return -1;
    }

    *out_len = 4 + addr_len + 2; // version, response, reserved, atyp, address, port
    *out_buf = malloc(*out_len);
    if(*out_buf == NULL) {
        return -1; // Memory allocation error
    }

    size_t offset = 0;
    (*out_buf)[offset++] = response->version;
    (*out_buf)[offset++] = response->response;
    (*out_buf)[offset++] = response->reserved;
    (*out_buf)[offset++] = response->add.atyp;

    switch(response->add.atyp) {
        case SOCKS5_ATYP_IPV4:
            memcpy(&(*out_buf)[offset], response->add.address.ipv4, 4);
            offset += 4;
            break;
        case SOCKS5_ATYP_DOMAINNAME:
            (*out_buf)[offset++] = response->add.address.domainname.length;
            memcpy(&(*out_buf)[offset], response->add.address.domainname.addr, response->add.address.domainname.length);
            offset += response->add.address.domainname.length;
            break;
        case SOCKS5_ATYP_IPV6:
            memcpy(&(*out_buf)[offset], response->add.address.ipv6, 16);
            offset += 16;
            break;
    }


    (*out_buf)[offset++] = (response->add.port >> 8) & 0xFF;
    (*out_buf)[offset++] = response->add.port & 0xFF;

    return 0;
}

