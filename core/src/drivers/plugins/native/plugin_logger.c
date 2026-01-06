/**
 * @file plugin_logger.c
 * @brief Centralized Plugin Logger Implementation for Native OpenPLC Plugins
 */

#include "plugin_logger.h"
#include "../../plugin_types.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

/* Maximum size for formatted log messages */
#define MAX_LOG_MESSAGE_SIZE 1024

bool plugin_logger_init(plugin_logger_t *logger, const char *plugin_name, void *runtime_args)
{
    if (!logger)
    {
        return false;
    }

    /* Initialize to invalid state */
    logger->is_valid = false;
    logger->log_info = NULL;
    logger->log_debug = NULL;
    logger->log_warn = NULL;
    logger->log_error = NULL;
    logger->plugin_name[0] = '\0';

    if (!plugin_name)
    {
        fprintf(stderr, "[PLUGIN_LOGGER] Error: plugin_name is NULL\n");
        return false;
    }

    /* Copy plugin name (with bounds checking) */
    strncpy(logger->plugin_name, plugin_name, sizeof(logger->plugin_name) - 1);
    logger->plugin_name[sizeof(logger->plugin_name) - 1] = '\0';

    if (!runtime_args)
    {
        fprintf(stderr, "[%s] Warning: runtime_args is NULL, logging will fall back to printf\n",
                logger->plugin_name);
        return true; /* Still return true - logger will fall back to printf */
    }

    /* Extract logging function pointers from runtime_args */
    plugin_runtime_args_t *args = (plugin_runtime_args_t *)runtime_args;

    logger->log_info = args->log_info;
    logger->log_debug = args->log_debug;
    logger->log_warn = args->log_warn;
    logger->log_error = args->log_error;

    /* Validate that we have at least the basic logging functions */
    if (logger->log_info && logger->log_error)
    {
        logger->is_valid = true;
    }
    else
    {
        fprintf(stderr, "[%s] Warning: Some log functions are NULL, falling back to printf\n",
                logger->plugin_name);
    }

    return true;
}

/**
 * @brief Internal helper to format and send log message
 */
static void plugin_logger_log(plugin_logger_t *logger, plugin_log_func_t log_func,
                              const char *level, const char *fmt, va_list args)
{
    char message[MAX_LOG_MESSAGE_SIZE];
    char prefixed_message[MAX_LOG_MESSAGE_SIZE];

    /* Format the user's message */
    vsnprintf(message, sizeof(message), fmt, args);

    /* Add plugin name prefix */
    snprintf(prefixed_message, sizeof(prefixed_message), "[%s] %s", logger->plugin_name, message);

    /* Use central logging if available, otherwise fall back to printf */
    if (log_func)
    {
        log_func("%s", prefixed_message);
    }
    else
    {
        printf("[%s] [%s] %s\n", logger->plugin_name, level, message);
    }
}

void plugin_logger_info(plugin_logger_t *logger, const char *fmt, ...)
{
    if (!logger || !fmt)
    {
        return;
    }

    va_list args;
    va_start(args, fmt);
    plugin_logger_log(logger, logger->log_info, "INFO", fmt, args);
    va_end(args);
}

void plugin_logger_debug(plugin_logger_t *logger, const char *fmt, ...)
{
    if (!logger || !fmt)
    {
        return;
    }

    va_list args;
    va_start(args, fmt);
    plugin_logger_log(logger, logger->log_debug, "DEBUG", fmt, args);
    va_end(args);
}

void plugin_logger_warn(plugin_logger_t *logger, const char *fmt, ...)
{
    if (!logger || !fmt)
    {
        return;
    }

    va_list args;
    va_start(args, fmt);
    plugin_logger_log(logger, logger->log_warn, "WARN", fmt, args);
    va_end(args);
}

void plugin_logger_error(plugin_logger_t *logger, const char *fmt, ...)
{
    if (!logger || !fmt)
    {
        return;
    }

    va_list args;
    va_start(args, fmt);
    plugin_logger_log(logger, logger->log_error, "ERROR", fmt, args);
    va_end(args);
}
