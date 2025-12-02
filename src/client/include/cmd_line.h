#ifndef CMD_LINE_H
#define CMD_LINE_H

#include <stdbool.h>
#include <stddef.h>

#define USERNAME_MAX 32
#define ROLE_MAX 16
#define PASSWORD_MAX 32
#define CANT_USERS_MAX 16

enum cmd_modes{
    CMD_NONE,
    CMD_GET_LOGS,
    CMD_GET_METRICS,
    CMD_USERS,
    CMD_ADD_USER,
    CMD_ROLE_SETTER,
    CMD_BUFFER_NEWSIZE,
    CMD_DELETE_USER,
    CMD_QUIT
};


typedef struct{
    char username[USERNAME_MAX];
    char password[PASSWORD_MAX];
} client_credentials_t;

typedef struct{
    client_credentials_t users[CANT_USERS_MAX];
    size_t cant_users;
    char auth_username[USERNAME_MAX];
    char auth_password[PASSWORD_MAX];
    int port;
    char *address;
    enum cmd_modes mode;
    char role[ROLE_MAX];
    unsigned long long buffer_size;
    char target_username[USERNAME_MAX];  // For operations targeting another user (like ROLE_SETTER, DELETE_USER)
} client_list_t;

void command_parse_args(int argc, char *argv[], client_list_t * config);

#endif // CMD_LINE_H