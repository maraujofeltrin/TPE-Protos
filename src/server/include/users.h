#ifndef SERVER_USERS_H
#define SERVER_USERS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>

#include "socks5.h"

/* Maximum number of users the server keeps in memory */
#define SERVER_MAX_USERS 256

typedef enum{
    ROLE_ADMIN,
    ROLE_USER
} user_role_t;

typedef struct user {
    char *username;
    char *password;
    user_role_t role;
} user_t;

/* Add a user to the in-memory list.
 * Returns 0 on success, -1 if the list is full, -2 if username already exists.
 */
int users_add(const char *username, const char *password, user_role_t role);
user_t * authenticate_user(const char *username, const char *password);


#endif /* SERVER_USERS_H */

