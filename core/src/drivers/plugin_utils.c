#include "plugin_utils.h"
#include "../plc_app/image_tables.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Wrapper function to get list of variable addresses
void get_var_list(size_t num_vars, size_t *indexes, void **result)
{
    for (size_t i = 0; i < num_vars; i++) {
        size_t idx = indexes[i];
        if (idx >= num_vars) {
            result[i] = NULL;
        } else {
            result[i] = ext_get_var_addr(idx);
        }
    }
}