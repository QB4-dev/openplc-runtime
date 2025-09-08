#ifndef LOG_H
#define LOG_H

#include <stdio.h>

typedef enum {
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR
} LogLevel;

/**
 * @brief Set the log level
 *
 * @param[in]  level  The log level to set
 */
void log_set_level(LogLevel level);

/**
 * @brief Log an informational message
 *
 * @param[in]  fmt  The format string
 * @param[in]  ...  The values to format
 */
void log_info(const char *fmt, ...);

/**
 * @brief Log a debug message
 *
 * @param[in]  fmt  The format string
 * @param[in]  ...  The values to format
 */
void log_debug(const char *fmt, ...);

/**
 * @brief Log a warning message
 *
 * @param[in]  fmt  The format string
 * @param[in]  ...  The values to format
 */
void log_warn(const char *fmt, ...);

/**
 * @brief Log an error message
 *
 * @param[in]  fmt  The format string
 * @param[in]  ...  The values to format
 */
void log_error(const char *fmt, ...);

#endif
