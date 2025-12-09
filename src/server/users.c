#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>

#include "include/users.h"

static user_t users_store[SERVER_MAX_USERS];
static size_t users_store_count = 0;
static int cant_logs = 0, pos_logs = 0;
static logs_t logs[MAX_LOGS];

bool has_users(void) {
	return users_store_count > 0;
}

void users_init(void) {
	users_store_count = 0;
	cant_logs = 0;
	pos_logs = 0;

	for(int i = 0; i < MAX_LOGS; i++){
		logs[i].username = NULL;
		logs[i].ip = NULL;
		logs[i].dest = NULL;
		logs[i].cant_bytes = 0;
		logs[i].time = 0;
	}

	for (int i = 0; i < SERVER_MAX_USERS; i++)
	{
		users_store[i].username = NULL;
		users_store[i].password = NULL;
		users_store[i].role = ROLE_INACTIVE;
	}
	
}

int users_add(const char * username, const char * password, user_role_t role) {
	if (!username || !password) return -1;
	for (size_t i = 0; i < users_store_count; ++i) {
		if (strcmp(users_store[i].username, username) == 0) {
			return -2; 
		}
	}
	if (users_store_count >= SERVER_MAX_USERS) {
		return -1;
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

int remove_user(const char * username) {
    if(!username) return -1;
    for (size_t i = 0; i < users_store_count; ++i) {
        if (strcmp(users_store[i].username, username) == 0) {
            free(users_store[i].username);
            free(users_store[i].password);
            users_store[i] = users_store[users_store_count - 1];
            users_store_count--;
            return 0;
        }
    }
    return -1;
}

user_t * authenticate_user(const char * username, const char * password) {
	if(!username || !password) return NULL;
	for (size_t i = 0; i < users_store_count; ++i) {
		if (strcmp(users_store[i].username, username) == 0) {
			if (strcmp(users_store[i].password, password) == 0) {
				return &users_store[i];
			} else {
				return NULL;
			}
		}
	}
	return NULL;
}

user_t * find_user_by_name(const char * username) {
	if(!username) return NULL;
	for (size_t i = 0; i < users_store_count; ++i) {
		if (strcmp(users_store[i].username, username) == 0) {
			return &users_store[i];
		}
	}
	return NULL;
}

bool permission_user_command(char * user, const char * command) {
	if (!user || !command) return false;
	
	user_role_t role = get_user_role(user);
	if (role == ROLE_ADMIN) {
		return true; 
	}
	if (strcmp(command, "LIST") == 0 || strcmp(command, "GET_ALL_METRICS") == 0) {
		return true;
	}	
	return false;
}

user_role_t get_user_role(const char * username) {
	if (!username) return -1;
	for (size_t i = 0; i < users_store_count; ++i) {
		if (strcmp(users_store[i].username, username) == 0) {
			return users_store[i].role;
		}
	}
	return -1;
}

const char * get_user_list() {
	static char list[4096];
	int pos = 0;
	list[0] = '\0';

	for (size_t i = 0; i < users_store_count; ++i) {
		const char *role_str = (users_store[i].role == ROLE_ADMIN) ? "admin" : "user";
		int written = snprintf(list + pos, sizeof(list) - pos,
							   "%s %s\n",
							   users_store[i].username,
							   role_str);
		if (written < 0 || written >= (int)(sizeof(list) - pos))
			break;
		pos += written;
	}
	if (pos < (int)sizeof(list) - 3) {
		list[pos++] = '.';
		list[pos++] = '\n';
		list[pos] = '\0';
	}
	return list;
}

const char * get_all_logs(void){
	static char buf[MAX_LOGS];
	int p = 0;
	buf[0] = '\0';

	for(int i = 0; i < cant_logs; i++){
		int j = (pos_logs - cant_logs + i) % MAX_LOGS;

		int w = snprintf(buf + p, sizeof(buf) - p, "%s %s %s %lu\n",
			logs[j].username,
			logs[j].ip,
			logs[j].dest,
			logs[j].cant_bytes
		);

		if (w < 0 || w >= (int)(sizeof(buf) - p)) {
			break;
		}
		p += w;
	}
	
	if (p < (int)sizeof(buf) - 3) {
		buf[p++] = '.';
		buf[p++] = '\n';
		buf[p] = '\0';
	}
	
	return buf;
}

int access_logs(const char * username, const char * ip, const char * dest, size_t cant_bytes){
	if(!username || !ip || !dest){
		return -1;
	}
	
	if(logs[pos_logs].username) free(logs[pos_logs].username);
	if(logs[pos_logs].ip) free(logs[pos_logs].ip);
	if(logs[pos_logs].dest) free(logs[pos_logs].dest);
	
	logs[pos_logs].username = strdup(username);
	logs[pos_logs].ip = strdup(ip);
	logs[pos_logs].dest = strdup(dest);
	
	if(!logs[pos_logs].username || !logs[pos_logs].ip || !logs[pos_logs].dest) {
		if(logs[pos_logs].username) free(logs[pos_logs].username);
		if(logs[pos_logs].ip) free(logs[pos_logs].ip);
		if(logs[pos_logs].dest) free(logs[pos_logs].dest);
		logs[pos_logs].username = NULL;
		logs[pos_logs].ip = NULL;
		logs[pos_logs].dest = NULL;
		return -1;
	}
	
	logs[pos_logs].cant_bytes = cant_bytes;
	logs[pos_logs].time = time(NULL);
	
	int ret = pos_logs;
	pos_logs = (pos_logs + 1) % MAX_LOGS;
	if(cant_logs < MAX_LOGS){
		cant_logs++;	
	}
	return ret;	

}

void free_users(void) {
	for (size_t i = 0; i < users_store_count; ++i) {
		free(users_store[i].username);
		free(users_store[i].password);
		users_store[i].username = NULL;
		users_store[i].password = NULL;
		users_store[i].role = ROLE_INACTIVE;
	}
	users_store_count = 0;
	
	for (int i = 0; i < MAX_LOGS; i++) {
		if(logs[i].username) {
			free(logs[i].username);
			logs[i].username = NULL;
		}
		if(logs[i].ip) {
			free(logs[i].ip);
			logs[i].ip = NULL;
		}
		if(logs[i].dest) {
			free(logs[i].dest);
			logs[i].dest = NULL;
		}
	}
	cant_logs = 0;
	pos_logs = 0;
}