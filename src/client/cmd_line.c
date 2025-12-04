#include "include/cmd_line.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

static void command_help(const char * cmd){
    fprintf(stderr,
        "Commands: %s [OPTIONS]\n\n"
        "  -h                                Show help and exit\n"
        "  -v                                Show version and exit\n"
        "  -p <port>                         Server port (default: 8080)\n"
        "  -u <user>:<pass>                  Authentication credentials\n"
        "  -l                                Get all server logs                      (GET_LOGS)\n"
        "  -m                                Get metrics                              (GET_METRICS)\n"
        "  -U                                List users                               (USERS)\n"
        "  -a <username>:<password>          Add user with role user                  (ADD_USER)\n"
        "  -r <username>:<role>              Set role for user                        (ROLE_SETTER)\n"
        "  -b <buffer_size>                  Set buffer size (in bytes)               (BUFFER_NEWSIZE)\n"
        "  -d <username>                     Delete user                              (DELETE_USER)\n"
        "  -q                                Quit                                     (QUIT)\n",
        cmd
    );
}

static void command_version(void) {
    fprintf(stdout, "SOCKS5 Management Client v1.0\n");
}

static char* duplicate_string(const char *source) {
    if (!source) return NULL;
    size_t length = strlen(source) + 1;
    char *duplicate = malloc(length);
    if (duplicate) {
        memcpy(duplicate, source, length);
    }
    return duplicate;
}

static void extract_credentials(const char *input, char *username_out, char *password_out) {
    char *temp = duplicate_string(input);
    if (!temp) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    
    char *delimiter = strchr(temp, ':');
    if (!delimiter) {
        fprintf(stderr, "Invalid credentials format '%s'. Expected format: username:password\n", input);
        free(temp);
        exit(EXIT_FAILURE);
    }
    
    *delimiter = '\0';
    delimiter++;
    
    snprintf(username_out, USERNAME_MAX, "%s", temp);
    snprintf(password_out, PASSWORD_MAX, "%s", delimiter);
    
    free(temp);
}

static void parse_role_assignment(const char *input, char *username_out, char *role_out) {
    char *temp = duplicate_string(input);
    if (!temp) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    
    char *delimiter = strchr(temp, ':');
    if (!delimiter) {
        fprintf(stderr, "Invalid role format '%s'. Expected format: username:role\n", input);
        free(temp);
        exit(EXIT_FAILURE);
    }
    
    *delimiter = '\0';
    delimiter++;
    
    snprintf(username_out, USERNAME_MAX, "%s", temp);
    snprintf(role_out, ROLE_MAX, "%s", delimiter);
    
    free(temp);
}

void command_parse_args(int argc, char *argv[], client_list_t * config){
    config->mode = CMD_NONE;
    config->cant_users = 0;
    config->address = "127.0.0.1";
    config->port = 8080;
    config->auth_username[0] = '\0';
    config->auth_password[0] = '\0';
    config->role[0] = '\0';
    config->buffer_size = 0;
    
    int opt;
    static struct option long_options[] = {
        {"help",    no_argument,       NULL, 'h'},
        {"version", no_argument,       NULL, 'v'},
        {"port",    required_argument, NULL, 'p'},
        {"user",    required_argument, NULL, 'u'},
        {"logs",    no_argument,       NULL, 'l'},
        {"metrics", no_argument,       NULL, 'm'},
        {"users",   no_argument,       NULL, 'U'},
        {"add",     required_argument, NULL, 'a'},
        {"role",    required_argument, NULL, 'r'},
        {"buffer",  required_argument, NULL, 'b'},
        {"delete",  required_argument, NULL, 'd'},
        {"quit",    no_argument,       NULL, 'q'},
        {0, 0, 0, 0}
    };
    
    const char *option_string = "hvp:u:lmUa:r:b:d:q";
    
    while((opt = getopt_long(argc, argv, option_string, long_options, NULL)) != -1){
        switch(opt){
            case 'h':
                command_help(argv[0]);
                exit(EXIT_SUCCESS);
                
            case 'v':
                command_version();
                exit(EXIT_SUCCESS);
                
            case 'p':
                config->port = (int)atoi(optarg);
                if (config->port <= 0 || config->port > 65535) {
                    fprintf(stderr, "Invalid port number: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
                
            case 'u':
                extract_credentials(optarg, config->auth_username, config->auth_password);
                break;
                
            case 'l':
                config->mode = CMD_GET_LOGS;
                break;
                
            case 'm':
                config->mode = CMD_GET_METRICS;
                break;
                
            case 'U':
                config->mode = CMD_USERS;
                break;
                
            case 'a':
                if (config->cant_users >= CANT_USERS_MAX) {
                    fprintf(stderr, "Maximum number of users reached\n");
                    exit(EXIT_FAILURE);
                }
                extract_credentials(optarg, config->users[config->cant_users].username, config->users[config->cant_users].password);
                config->cant_users++;
                config->mode = CMD_ADD_USER;
                break;
                
            case 'r':
                parse_role_assignment(optarg, config->target_username, config->role);
                config->mode = CMD_ROLE_SETTER;
                break;
                
            case 'b':
                config->buffer_size = strtoull(optarg, NULL, 10);
                if (config->buffer_size == 0) {
                    fprintf(stderr, "Invalid buffer size: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                config->mode = CMD_BUFFER_NEWSIZE;
                break;
                
            case 'd':
                strncpy(config->target_username, optarg, USERNAME_MAX - 1);
                config->target_username[USERNAME_MAX - 1] = '\0';
                config->mode = CMD_DELETE_USER;
                break;
                
            case 'q':
                config->mode = CMD_QUIT;
                break;
                
            default:
                command_help(argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    
    if (config->mode == CMD_NONE) {
        fprintf(stderr, "Error: No command specified\n\n");
        command_help(argv[0]);
        exit(EXIT_FAILURE);
    }
}

