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
    ROLE_USER
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

/* Add a user to the in-memory list.
 * Returns 0 on success, -1 if the list is full, -2 if username already exists.
 */
int users_add(const char *username, const char *password, user_role_t role);

/* Remove a user from the in-memory list.
 * Returns 0 on success, -1 if not found.
 */
int remove_user(const char *username);

/* Authenticate a user with username and password.
 * Returns pointer to user_t if successful, NULL otherwise.
 */
user_t * authenticate_user(const char *username, const char *password);

/* Check if a user has permission to execute a command.
 * Returns true if allowed, false otherwise.
 */
bool permission_user_command(char *user, const char *command);

/* Get the role of a user by username.
 * Returns the user role, or -1 if not found.
 */
user_role_t get_user_role(const char *username);

/* Get a formatted list of all users.
 * Returns a static string with user list.
 */
const char * get_user_list(void);

const char * get_all_logs(void);

#endif /* SERVER_USERS_H */

