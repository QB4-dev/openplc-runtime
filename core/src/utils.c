#include <unistd.h>
#include <stdlib.h>
#include "utils.h"

unsigned long long *ext_common_ticktime__ = NULL;
unsigned long tick__ = 0;

void normalize_timespec(struct timespec *ts) {
    while (ts->tv_nsec >= 1e9) {
        ts->tv_nsec -= 1e9;
        ts->tv_sec++;
    }
}

void sleep_until(struct timespec *ts, long period_ns) {
    ts->tv_nsec += period_ns;
    normalize_timespec(ts);
    #ifdef __APPLE__
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);

        time_t sec = ts->tv_sec - now.tv_sec;
        long nsec = ts->tv_nsec - now.tv_nsec;
        if (nsec < 0) {
            nsec += 1000000000;
            sec -= 1;
        }
        struct timespec delay = { .tv_sec = sec, .tv_nsec = nsec };
        nanosleep(&delay, NULL);
    #else
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, ts, NULL);
    #endif
}


void timespec_diff(struct timespec *a, struct timespec *b, struct timespec *result) 
{
    // Calculate the difference in seconds
    result->tv_sec = a->tv_sec - b->tv_sec;

    // Calculate the difference in nanoseconds
    result->tv_nsec = a->tv_nsec - b->tv_nsec;

    // Handle borrowing if nanoseconds are negative
    if (result->tv_nsec < 0) 
    {
        // Borrow 1 second (1e9 nanoseconds)
        --result->tv_sec;
        result->tv_nsec += 1000000000L;
    }
}
