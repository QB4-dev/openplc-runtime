#ifndef UTILS_H
#define UTILS_H

#include <time.h>
#include <dlfcn.h>

#include "iec_types.h"
#include "log.h"

#define BUFFER_SIZE		1024

//IEC_BOOL *(*ext_bool_output)[8];
extern unsigned long long *ext_common_ticktime__;
extern unsigned long tick__;

void normalize_timespec(struct timespec *ts);
void sleep_until(struct timespec *ts, long period_ns);
void timespec_diff(struct timespec *a, struct timespec *b, struct timespec *result);
void symbols_init(void);

#endif // UTILS_H
