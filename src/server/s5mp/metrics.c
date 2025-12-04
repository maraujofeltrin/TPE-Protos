#include "../include/metrics.h"

static uint64_t total_connections;
static uint64_t active_connections;
static uint64_t total_bytes_transferred;

void metrics_init(void) {
    total_connections = 0;
    active_connections = 0;
    total_bytes_transferred = 0;
}
void metrics_connection_opened(void) {
    total_connections++;
    active_connections++;
}
void metrics_connection_closed(void) {
    if (active_connections > 0) {
        active_connections--;
    }
}

void metrics_data_transferred(uint64_t bytes) {
    total_bytes_transferred += bytes;
}
uint64_t metrics_get_total_connections(void) {
    return total_connections;
}

uint64_t metrics_get_active_connections(void) {
    return active_connections;
}

uint64_t metrics_get_total_data_transferred(void) {
    return total_bytes_transferred;
}

