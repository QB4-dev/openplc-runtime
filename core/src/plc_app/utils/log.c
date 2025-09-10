#include "log.h"
#include <pthread.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

static LogLevel current_level = LOG_LEVEL_INFO;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void log_set_level(LogLevel level) { current_level = level; }

static const char *level_to_str(LogLevel level) 
{
    switch (level) 
    {
      case LOG_LEVEL_DEBUG:
          return "DEBUG";
      case LOG_LEVEL_INFO:
          return "INFO";
      case LOG_LEVEL_WARN:
          return "WARN";
      case LOG_LEVEL_ERROR:
          return "ERROR";
      default:
          return "UNKNOWN";
    }
}

static void log_write(LogLevel level, const char *fmt, va_list args) 
{
    if (level < current_level)
    {
        return;
    }

    pthread_mutex_lock(&log_mutex);

    time_t now = time(NULL);
    struct tm t;
    localtime_r(&now, &t);

    char time_buf[20];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &t);

    fprintf(stderr, "[%s] [%s] ", time_buf, level_to_str(level));
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");

    pthread_mutex_unlock(&log_mutex);
}

void log_info(const char *fmt, ...) 
{
    va_list args;
    va_start(args, fmt);
    log_write(LOG_LEVEL_INFO, fmt, args);
    va_end(args);
}

void log_debug(const char *fmt, ...) 
{
    va_list args;
    va_start(args, fmt);
    log_write(LOG_LEVEL_DEBUG, fmt, args);
    va_end(args);
}

void log_warn(const char *fmt, ...) 
{
    va_list args;
    va_start(args, fmt);
    log_write(LOG_LEVEL_WARN, fmt, args);
    va_end(args);
}

void log_error(const char *fmt, ...) 
{
    va_list args;
    va_start(args, fmt);
    log_write(LOG_LEVEL_ERROR, fmt, args);
    va_end(args);
}
