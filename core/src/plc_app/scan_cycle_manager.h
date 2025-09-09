#ifndef SCAN_CYCLE_MANAGER_H
#define SCAN_CYCLE_MANAGER_H

typedef struct
{
    uint64_t scan_time_min;
    uint64_t scan_time_max;
    int64_t scan_time_avg;

    uint64_t cycle_time_min;
    uint64_t cycle_time_max;
    uint64_t cycle_time_avg;

    int64_t cycle_latency_min;
    int64_t cycle_latency_max;
    int64_t cycle_latency_avg;

    uint64_t scan_count;
    uint64_t overruns;
} plc_timing_stats_t;

void scan_cycle_time_start();
void scan_cycle_time_end();

#endif // SCAN_CYCLE_MANAGER_H