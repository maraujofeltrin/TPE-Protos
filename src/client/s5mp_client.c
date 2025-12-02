#include "include/s5mp_client.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>

int sockfd = -1;
bool connected = false;

static command_status_types parse_response_code(const char *line);
static ssize_t send_full(int fd, const char *buf, size_t len);
static ssize_t recv_line(int fd, char *buf, size_t max_len);

static ssize_t send_full(int fd, const char *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = send(fd, buf + total, len - total, 0);
        if (n <= 0) return n;
        total += n;
    }
    return total;
}

static ssize_t recv_line(int fd, char *buf, size_t max_len) {
    size_t i = 0;
    while (i < max_len - 1) {
        ssize_t n = recv(fd, buf + i, 1, 0);
        if (n <= 0) return n;
        if (buf[i] == '\n') {
            buf[i + 1] = '\0';
            return i + 1;
        }
        i++;
    }
    buf[i] = '\0';
    return i;
}

void close_connection(){
    if(connected){
        close(sockfd);
        connected = false;
        sockfd = -1;
    }
}

command_status_types add_user_client(s5mp_credentials_t new_user){
    if(!connected){
        return SERVER_ERROR_RESP;
    }
    char aux[128];
    int n = snprintf(aux, sizeof(aux), "ADD-USER %s %s %s\n", new_user.username, new_user.password, new_user.role);
    if(n < 0 || n >= (int)sizeof(aux)) return COMMAND_ERROR_RESP;
    if(send_full(sockfd, aux, strlen(aux)) <= 0) return SERVER_ERROR_RESP;
    char line[BUFFER_MAX];
    if(recv_line(sockfd, line, sizeof(line)) <= 0) return SERVER_ERROR_RESP;
    return parse_response_code(line);
}

command_status_types set_size_buffer_client(uint64_t size){
    if(!connected){
        return SERVER_ERROR_RESP;
    }
    char aux[64];
    int n = snprintf(aux, sizeof(aux), "SET-BUFFER-SIZE %lu\n", size);
    if(n < 0 || n >= (int)sizeof(aux)) return COMMAND_ERROR_RESP;
    if(send_full(sockfd, aux, strlen(aux)) <= 0) return SERVER_ERROR_RESP;
    char line[BUFFER_MAX];
    if(recv_line(sockfd, line, sizeof(line)) <= 0) return SERVER_ERROR_RESP;
    return parse_response_code(line);
}

command_status_types remove_user_client(const char * name){
    if(!connected){
        return SERVER_ERROR_RESP;
    }
    char aux[64];
    int n = snprintf(aux, sizeof(aux), "REMOVE-USER %s\n", name);
    if(n < 0 || n >= (int)sizeof(aux)) return COMMAND_ERROR_RESP;
    if(send_full(sockfd, aux, strlen(aux)) <= 0) return SERVER_ERROR_RESP;
    char line[BUFFER_MAX];
    if(recv_line(sockfd, line, sizeof(line)) <= 0) return SERVER_ERROR_RESP;
    return parse_response_code(line);
}

command_status_types set_role_client(const char *username, const char *role) {
    if (!connected) {
        return SERVER_ERROR_RESP;
    }
    char buf[128];
    int n = snprintf(buf, sizeof(buf), "SET-ROLE %s %s\n", username, role);
    if (n < 0 || n >= (int)sizeof(buf)){ 
        return COMMAND_ERROR_RESP;
    }
    if (send_full(sockfd, buf, strlen(buf)) <= 0){
         return SERVER_ERROR_RESP;
    }
    char line[BUFFER_MAX];
    if (recv_line(sockfd, line, sizeof(line)) <= 0){ 
        return SERVER_ERROR_RESP;
    }
    return parse_response_code(line);
}

command_status_types get_all_users(user_list_t * list){
    if(!connected){
        return SERVER_ERROR_RESP;
    }
    char l[BUFFER_MAX];
    if(send_full(sockfd, "GET-USERS\n", 10) <= 0) return SERVER_ERROR_RESP;
    if(recv_line(sockfd, l, sizeof(l)) <= 0) return SERVER_ERROR_RESP;
    if(strncmp(l, "200", 3) == 0){
        size_t c = 0, cap = 16;
        list->users = malloc(cap * sizeof(s5mp_credentials_t));
        list->cant_users = 0;

        while(recv_line(sockfd, l, sizeof(l)) > 0){
            if(strcmp(l, ".\n") == 0) break;
            char username[64], password[64], role[16];
            if(sscanf(l, "%63s %63s %15s", username, password, role) != 3){
                free(list->users);
                return COMMAND_ERROR_RESP;
            }
            strncpy(list->users[c].username, username, 32);
            strncpy(list->users[c].password, password, 32);
            strncpy(list->users[c].role, role, 16);
            c++;
        }

        list->cant_users = c;
        return SUCCESS_RESP;
    }
    else if(strncmp(l, "403", 3) == 0){
        return AUTHENTICATION_ERROR_RESP;
    }
    else{
        return COMMAND_ERROR_RESP;
    }
}

command_status_types get_logs_client(logs_list_t * list){
    if(!connected){
        return SERVER_ERROR_RESP;
    }
    char l[BUFFER_MAX];
    if(send_full(sockfd, "GET-LOGS\n", 9) <= 0) return SERVER_ERROR_RESP;
    if(recv_line(sockfd, l, sizeof(l)) <= 0) return SERVER_ERROR_RESP;
    if(strncmp(l, "200", 3) == 0){
        size_t c = 0, cap = 16;
        list->logs = malloc(cap * sizeof(logs_t));
        list->cant_logs = 0;

        while(recv_line(sockfd, l, sizeof(l)) > 0){
            if(strcmp(l, ".\n") == 0) break;
            char username[64], ip[64], dest[128];
            uint64_t bytes;
            if(sscanf(l, "%63s %63s %127s %lu", username, ip, dest, &bytes) != 4){
                free(list->logs);
                return COMMAND_ERROR_RESP;
            }
            list->logs[c].username = malloc(strlen(username) + 1);
            list->logs[c].ip = malloc(strlen(ip) + 1);
            list->logs[c].dest = malloc(strlen(dest) + 1);
            strcpy(list->logs[c].username, username);
            strcpy(list->logs[c].ip, ip);
            strcpy(list->logs[c].dest, dest);
            list->logs[c].cant_bytes = bytes;
            list->logs[c].time = time(NULL);
            c++;
        }

        list->cant_logs = c;
        return SUCCESS_RESP;
    }
    else if(strncmp(l, "403", 3) == 0){
        return AUTHENTICATION_ERROR_RESP;
    }
    else{
        return COMMAND_ERROR_RESP;
    }
}

command_status_types get_metrics_client(client_metrics_t * metrics){
    if(!connected){
        return SERVER_ERROR_RESP;
    }
    char l[BUFFER_MAX];
    
    if(send_full(sockfd, "GET_METRICS\n", strlen("GET_METRICS\n")) <= 0) return SERVER_ERROR_RESP;
    
    if(recv_line(sockfd, l, sizeof(l)) <= 0 || strncmp(l, "200", 3) != 0) return SERVER_ERROR_RESP;
    
    while (recv_line(sockfd, l, sizeof(l)) > 0)
    {
        if(strcmp(l, ".\n") == 0) break;
        if(strncmp(l, "total_connections ", 18) == 0){
            metrics->total_connections = strtoull(l + 18, NULL, 10);
        }
        else if(strncmp(l, "total_bytes_transferred ", 24) == 0){
            metrics->total_bytes_transferred = strtoull(l + 24, NULL, 10);
        } 
        else if(strncmp(l, "active_connections ", 19) == 0){
            metrics->active_connections = strtoull(l + 19, NULL, 10);  
        }
    }

    return SUCCESS_RESP;
}

command_status_types quit_client(){
    if(!connected){
        return SERVER_ERROR_RESP;
    }

    if(send_full(sockfd, "QUIT\n", strlen("QUIT\n")) <= 0){
        return SERVER_ERROR_RESP;
    }

    char line[BUFFER_MAX];
    if(recv_line(sockfd, line, sizeof(line)) <= 0){
        return SERVER_ERROR_RESP;
    }

    if(strncmp(line, "200", 3) == 0){
        close_connection();
        return SUCCESS_RESP;
    }
    return SERVER_ERROR_RESP;
}

void free_user_list(user_list_t * list){
    if(list->users != NULL){
        free(list->users);
        list->users = NULL;
        list->cant_users = 0;
    }
}

void free_log_list(logs_list_t * list){
    if(list->logs != NULL){
        for(uint64_t i = 0; i < list->cant_logs; i++){
            free(list->logs[i].username);
            free(list->logs[i].ip);
            free(list->logs[i].dest);
        }
        free(list->logs);
        list->logs = NULL;
        list->cant_logs = 0;
    }
}

status_types connect_to_server(const char * ip, uint16_t port, const char * username, const char * password){
    if(connected){
        return SERVER_ERROR;
    }

    struct addrinfo hints = {0}, *res, *p;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char portstr[6];
    snprintf(portstr, sizeof(portstr), "%u", port);

    int status = getaddrinfo(ip, portstr, &hints, &res);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return SERVER_ERROR;
    }

    for (p = res; p; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd < 0) continue;
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == 0) {
            connected = true;
            break;
        }
        close(sockfd);
    }
    freeaddrinfo(res);
    
    if (!connected) return SERVER_ERROR;

    char buf[BUFFER_MAX];
    if(send_full(sockfd, "HELLO S5MP/1.0\n", strlen("HELLO S5MP/1.0\n")) <= 0){
        close_connection();
        return SERVER_ERROR;
    }
    
    if (recv_line(sockfd, buf, sizeof(buf)) <= 0 || strncmp(buf, "200", 3) != 0){
        close_connection();
        return SERVER_ERROR;
    }

    snprintf(buf, sizeof(buf), "AUTH %s %s\n", username, password);
    if(send_full(sockfd, buf, strlen(buf)) <= 0){
        close_connection();
        return SERVER_ERROR;
    }
    
    if (recv_line(sockfd, buf, sizeof(buf)) <= 0){
        close_connection();
        return SERVER_ERROR;
    }
    
    if(strncmp(buf, "200", 3) != 0){
        close_connection();
        return AUTHENTICATION_ERROR;
    }

    return SUCCESS;
}


static command_status_types parse_response_code(const char *line) {
    if(strncmp(line, "200", 3) == 0)      return SUCCESS_RESP;
    if(strncmp(line, "400", 3) == 0)      return COMMAND_ERROR_RESP;
    if(strncmp(line, "403", 3) == 0)      return AUTHENTICATION_ERROR_RESP;
    return SERVER_ERROR_RESP;
}



