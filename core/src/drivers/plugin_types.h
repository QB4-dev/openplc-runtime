/**
 * @file plugin_types.h
 * @brief Common type definitions for OpenPLC plugins
 *
 * This header defines the essential types and structures shared between
 * the plugin driver system and native plugins. It provides:
 * - Logging function pointer types
 * - The plugin_runtime_args_t structure for runtime buffer access
 *
 * Both Python and native plugins receive a pointer to plugin_runtime_args_t
 * during initialization, giving them access to PLC I/O buffers, mutex
 * functions, and centralized logging.
 */

#ifndef PLUGIN_TYPES_H
#define PLUGIN_TYPES_H

#include "../lib/iec_types.h"
#include <pthread.h>

/**
 * @brief Logging function pointer types
 *
 * These function pointers are provided to plugins for routing log messages
 * through the central OpenPLC logging system. Messages logged through these
 * functions will appear in the OpenPLC Editor's log viewer.
 */
typedef void (*plugin_log_info_func_t)(const char *fmt, ...);
typedef void (*plugin_log_debug_func_t)(const char *fmt, ...);
typedef void (*plugin_log_warn_func_t)(const char *fmt, ...);
typedef void (*plugin_log_error_func_t)(const char *fmt, ...);

/**
 * @brief Runtime buffer access structure for plugins
 *
 * This structure is passed to plugins during initialization, providing
 * access to:
 * - PLC I/O buffers (bool, byte, int, dint, lint for inputs/outputs/memory)
 * - Mutex functions for thread-safe buffer access
 * - Plugin-specific configuration file path
 * - Buffer size information
 * - Centralized logging functions
 *
 * Plugins should use mutex_take/mutex_give when accessing buffers to ensure
 * thread safety with the PLC scan cycle.
 */
typedef struct
{
    /* Buffer pointers */
    IEC_BOOL *(*bool_input)[8];
    IEC_BOOL *(*bool_output)[8];
    IEC_BYTE **byte_input;
    IEC_BYTE **byte_output;
    IEC_UINT **int_input;
    IEC_UINT **int_output;
    IEC_UDINT **dint_input;
    IEC_UDINT **dint_output;
    IEC_ULINT **lint_input;
    IEC_ULINT **lint_output;
    IEC_UINT **int_memory;
    IEC_UDINT **dint_memory;
    IEC_ULINT **lint_memory;
    IEC_BOOL *(*bool_memory)[8];

    /* Mutex functions for thread-safe buffer access */
    int (*mutex_take)(pthread_mutex_t *mutex);
    int (*mutex_give)(pthread_mutex_t *mutex);
    pthread_mutex_t *buffer_mutex;

    /* Plugin configuration */
    char plugin_specific_config_file_path[256];

    /* Buffer size information */
    int buffer_size;
    int bits_per_buffer;

    /* Logging functions - route messages through central logging system */
    plugin_log_info_func_t log_info;
    plugin_log_debug_func_t log_debug;
    plugin_log_warn_func_t log_warn;
    plugin_log_error_func_t log_error;
} plugin_runtime_args_t;

#endif /* PLUGIN_TYPES_H */
