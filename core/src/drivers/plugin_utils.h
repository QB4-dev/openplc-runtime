#ifndef PLUGIN_UTILS_H
#define PLUGIN_UTILS_H

#include <stddef.h>

void get_var_list(size_t num_vars, size_t *indexes, void **result);
size_t get_var_size(size_t idx);

#endif // PLUGIN_UTILS_H