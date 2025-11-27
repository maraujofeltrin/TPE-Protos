#ifndef METRICS_H_
#define METRICS_H_

#include <stdint.h>

void metrics_init(void);
void metrics_connection_opened(void);
void metrics_connection_closed(void);
void metrics_data_transferred(uint64_t bytes);

uint64_t metrics_get_total_connections(void);
uint64_t metrics_get_active_connections(void);
uint64_t metrics_get_total_data_transferred(void);

#endif