#include <stdio.h>
#include <stdlib.h>
#include "include/cmd_line.h"
#include "include/s5mp_client.h"

int main(int argc, char **argv) {
    client_list_t args;
    command_parse_args(argc, argv, &args);

    const char *username = args.auth_username[0] != '\0' ? args.auth_username : NULL;
    const char *password = args.auth_password[0] != '\0' ? args.auth_password : NULL;

    status_types status = connect_to_server(args.address, args.port, username, password);
    if (status != SUCCESS) {
        fprintf(stderr, "Failed to connect or authenticate with server.\n");
        return -1;
    }

    
    command_status_types response;
    switch(args.mode) {
        case CMD_GET_LOGS: {
            logs_list_t log_list;
            response = get_logs_client(&log_list);
            if (response != SUCCESS_RESP) {
                printf("Failed to retrieve logs.\n");
                break;
            }
            for (size_t i = 0; i < log_list.cant_logs; i++) {
                printf("Log %zu: User: %s, IP: %s, Dest: %s, Bytes: %lu, Time: %s",
                       i + 1,
                       log_list.logs[i].username,
                       log_list.logs[i].ip,
                       log_list.logs[i].dest,
                       (unsigned long)log_list.logs[i].cant_bytes,
                       ctime(&log_list.logs[i].time));
            }
            free_log_list(&log_list);
            break;
        }
        case CMD_GET_METRICS: {
            client_metrics_t metrics;
            response = get_metrics_client(&metrics);
            if (response == SUCCESS_RESP) {
                printf("Total Connections: %lu\n", (unsigned long)metrics.total_connections);
                printf("Active Connections: %lu\n", (unsigned long)metrics.active_connections);
                printf("Total Bytes Transferred: %lu\n", (unsigned long)metrics.total_bytes_transferred);
            } else {
                printf("Failed to retrieve metrics.\n");
            }
            break;
        }
        case CMD_USERS: {
            user_list_t list;
            response = get_all_users(&list);
            if (response != SUCCESS_RESP) {
                printf("Failed to retrieve user list.\n");
                break;
            }
            for (size_t i = 0; i < list.cant_users; i++) {
                printf("User %zu: %s, Role: %s\n", i + 1, list.users[i].username, list.users[i].role);
            }
            free_user_list(&list);
            break;
        }
        case CMD_ADD_USER: {
            s5mp_credentials_t new_user = {
                .username = args.users[0].username,
                .password = args.users[0].password,
                .role = "user"
            };
            response = add_user_client(new_user);
            if (response == SUCCESS_RESP) {
                printf("User added successfully.\n");
            } else {
                printf("Failed to add user.\n");
            }
            break;
        }
        case CMD_ROLE_SETTER:
            response = set_role_client(args.target_username, args.role);
            if (response == SUCCESS_RESP) {
                printf("Role updated successfully.\n");
            } else {
                printf("Failed to update role.\n");
            }
            break;
        case CMD_BUFFER_NEWSIZE:
            response = set_size_buffer_client(args.buffer_size);
            if (response == SUCCESS_RESP) {
                printf("Buffer size updated successfully.\n");
            } else {
                printf("Failed to update buffer size.\n");
            }
            break;  
        case CMD_DELETE_USER:
            response = remove_user_client(args.target_username);
            if (response == SUCCESS_RESP) {
                printf("User deleted successfully.\n");
            } else {
                printf("Failed to delete user.\n");
            }
            break;
        case CMD_QUIT:
            printf("Exiting...\n");
            break;
        default:
            printf("Unknown command mode.\n");
            break;
    }
    
    close_connection();
    return 0;
}