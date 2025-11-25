#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "users.h"

/* Simple in-memory users storage */
static user_t users_store[SERVER_MAX_USERS];
static size_t users_store_count = 0;

int users_add(const char *username, const char *password, user_role_t role) {
	if (!username || !password) return -1;
	/* check duplicate */
	for (size_t i = 0; i < users_store_count; ++i) {
		if (strcmp(users_store[i].username, username) == 0) {
			return -2; /* already exists */
		}
	}
	if (users_store_count >= SERVER_MAX_USERS) {
		return -1; /* full */
	}
	char *uname = strdup(username);
	if (uname == NULL) return -1;
	char *pword = strdup(password);
	if (pword == NULL) {
		free(uname);
		return -1;
	}
	users_store[users_store_count].username = uname;
	users_store[users_store_count].password = pword;
	users_store[users_store_count].role = role;
	users_store_count++;
	return 0;
}

int remove_user(const char *username) {
    if(!username) return -1;
    for (size_t i = 0; i < users_store_count; ++i) {
        if (strcmp(users_store[i].username, username) == 0) {
            free(users_store[i].username);
            free(users_store[i].password);
            users_store[i] = users_store[users_store_count - 1];
            users_store_count--;
            return 0; /* success */
        }
    }
    return -1; /* not found */
}

user_t * authenticate_user(const char *username, const char *password) {
	if(!username || !password) return NULL;
	for (size_t i = 0; i < users_store_count; ++i) {
		if (strcmp(users_store[i].username, username) == 0) {
			if (strcmp(users_store[i].password, password) == 0) {
				return &users_store[i]; /* success */
			} else {
				return NULL; /* wrong password */
			}
		}
	}
	return NULL;
}