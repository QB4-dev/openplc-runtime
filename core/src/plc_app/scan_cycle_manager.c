#include <time.h>
#include <stdint.h>
#include <stdio.h>

#include "scan_cycle_manager.h"
#include "utils/utils.h"

static uint64_t expected_start_us = 0;
static uint64_t last_start_us = 0;

plc_timing_stats_t plc_timing_stats = 
{
    .scan_time_min = INT64_MAX,
    .cycle_latency_min = INT64_MAX,
    .cycle_time_avg = 0,
    .cycle_time_min = INT64_MAX,
    .cycle_latency_avg = 0,
    .scan_count = 0,
    .overruns = 0
};

static uint64_t ts_now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000ull + ts.tv_nsec / 1000;
}


void scan_cycle_time_start() 
{
    uint64_t now_us = ts_now_us();

    if (plc_timing_stats.scan_count == 0)
    {
        // Ignore full calculations for the first cycle
        expected_start_us = now_us + *ext_common_ticktime__ / 1000; // Convert ns to us
        last_start_us = now_us;
        plc_timing_stats.scan_count++;

        return;
    }

    // Calculate cycle time
    int64_t cycle_time_us = now_us - last_start_us;
    if (cycle_time_us < plc_timing_stats.cycle_time_min)
    {
        plc_timing_stats.cycle_time_min = cycle_time_us;
    }
    if (cycle_time_us > plc_timing_stats.cycle_time_max)
    {
        plc_timing_stats.cycle_time_max = cycle_time_us;
    }
    plc_timing_stats.cycle_time_avg += (cycle_time_us - plc_timing_stats.cycle_time_avg) / plc_timing_stats.scan_count;

    // Calculate cycle latency
    int64_t latency_us = (int64_t)(now_us - expected_start_us);
    if (latency_us < plc_timing_stats.cycle_latency_min)
    {
        plc_timing_stats.cycle_latency_min = latency_us;
    }
    if (latency_us > plc_timing_stats.cycle_latency_max)
    {
        plc_timing_stats.cycle_latency_max = latency_us;
    }
    plc_timing_stats.cycle_latency_avg += (latency_us - plc_timing_stats.cycle_latency_avg) / plc_timing_stats.scan_count;

    last_start_us = now_us;
    expected_start_us += *ext_common_ticktime__ / 1000; // Convert ns to us

    plc_timing_stats.scan_count++;
}

void scan_cycle_time_end() 
{
    uint64_t now_us = ts_now_us();

    // Calculate scan time
    int64_t scan_time_us = now_us - last_start_us;
    if (scan_time_us < plc_timing_stats.scan_time_min)
    {
        plc_timing_stats.scan_time_min = scan_time_us;
    }
    if (scan_time_us > plc_timing_stats.scan_time_max)
    {
        plc_timing_stats.scan_time_max = scan_time_us;
    }
    plc_timing_stats.scan_time_avg += (scan_time_us - plc_timing_stats.scan_time_avg) / plc_timing_stats.scan_count;

    // Check for overrun
    if (now_us > expected_start_us)
    {
        plc_timing_stats.overruns++;
    }
}