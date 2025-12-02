#ifndef SERVER_H_
#define SERVER_H_

#include <stdio.h>
#include "../../utils/include/selector.h"

int register_socks5_target_fd(fd_selector s, int fd, void *data);

#endif