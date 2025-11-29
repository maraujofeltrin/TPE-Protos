#ifndef S5MP_CLIENT_H
#define S5MP_CLIENT_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <sys/types.h>


#define BUFFER_MAX 1024



typedef struct{
    char *username;
    char *password;
    char *role;
}client_credentials_t;

typedef struct user_list{
    client_credentials_t * users;
    uint64_t cant_users;
}user_list_t;

typedef struct{
    uint64_t total_connections;
    uint64_t active_connections;
    uint64_t total_bytes_transferred;
}client_metrics_t;

typedef struct{
    char * command_name;
    char * key;
    char * value;
}command;

typedef struct logs{
    char * username;
    char * ip;
    char * dest;
    uint64_t cant_bytes;
    time_t time;
}logs_t;

typedef struct{
    logs_t * logs;
    uint64_t cant_logs;
}logs_list_t;

typedef enum{
    SUCCESS,
    AUTHENTICATION_ERROR,
    SERVER_ERROR
} status_types;

typedef enum{
    SUCCESS_RESP,
    AUTHENTICATION_ERROR_RESP,
    SERVER_ERROR_RESP,
    COMMAND_ERROR_RESP
} command_status_types;

void free_log_list(logs_list_t * list);
void free_user_list(user_list_t * list);
status_types connect_to_server(const char * ip, uint16_t port, const char * username, const char * password);
void close_connection();
command_status_types add_user_client(client_credentials_t new_user);
command_status_types set_size_buffer_client(uint64_t size);
command_status_types remove_user_client(const char * name);
command_status_types set_role_client(const char *username, const char *role);
command_status_types get_metrics_client(client_metrics_t * metrics);
command_status_types get_all_users(user_list_t * list);
command_status_types get_logs_client(logs_list_t * list);


#endif