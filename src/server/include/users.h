#ifndef SERVER_USERS_H
#define SERVER_USERS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>

#include "socks5.h"

#define SERVER_MAX_USERS 256
#define MAX_LOGS 1024

typedef enum{
    ROLE_ADMIN,
    ROLE_USER,
    ROLE_INACTIVE
} user_role_t;

typedef struct user {
    char *username;
    char *password;
    user_role_t role;
} user_t;

typedef struct logs{
    char * username;
    char * ip;
    char * dest;
    uint64_t cant_bytes;
    time_t time;
}logs_t;

int users_add(const char *username, const char *password, user_role_t role);
int remove_user(const char *username);
user_t * authenticate_user(const char *username, const char *password);
user_t * find_user_by_name(const char * username);
bool permission_user_command(char *user, const char *command);
user_role_t get_user_role(const char *username);
const char * get_user_list(void);

const char * get_all_logs(void);

void free_users(void);

void users_init(void);

#endif 

