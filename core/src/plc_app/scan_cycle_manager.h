#ifndef SCAN_CYCLE_MANAGER_H
#define SCAN_CYCLE_MANAGER_H

#include <stdbool.h>
#include <stdint.h>

typedef struct
{
    int64_t scan_time_min;
    int64_t scan_time_max;
    int64_t scan_time_avg;

    int64_t cycle_time_min;
    int64_t cycle_time_max;
    int64_t cycle_time_avg;

    int64_t cycle_latency_min;
    int64_t cycle_latency_max;
    int64_t cycle_latency_avg;

    int64_t scan_count;
    int64_t overruns;
} plc_timing_stats_t;

void scan_cycle_time_start();
void scan_cycle_time_end();

// Thread-safe function to get a snapshot of timing stats
// Returns true if stats are valid (scan_count > 0), false otherwise
bool get_timing_stats_snapshot(plc_timing_stats_t *snapshot);

// Format timing stats as a response string for the STATS command
// Returns the number of characters written (excluding null terminator)
int format_timing_stats_response(char *buffer, size_t buffer_size);

#endif // SCAN_CYCLE_MANAGER_H
