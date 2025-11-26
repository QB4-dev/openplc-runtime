#ifndef PLUGIN_UTILS_H
#define PLUGIN_UTILS_H

#include <stddef.h>
#include <stdint.h>

void get_var_list(size_t num_vars, size_t *indexes, void **result);
size_t get_var_size(size_t idx);
uint16_t get_var_count(void);

#endif // PLUGIN_UTILS_H