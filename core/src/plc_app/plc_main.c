#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "image_tables.h"
#include "log.h"
#include "plcapp_manager.h"
#include "utils.h"
#include "watchdog.h"

extern atomic_long plc_heartbeat = 0;
volatile sig_atomic_t keep_running = 1;
time_t start_time, end_time;

// Define the max/min/avg/total cycle and latency variables used in REAL-TIME
// computation(in nanoseconds)
long cycle_avg, cycle_max, cycle_min, cycle_total;
long latency_avg, latency_max, latency_min, latency_total;
// Define the start, end, cycle time and latency time variables
struct timespec cycle_start, cycle_end, cycle_time;
struct timespec timer_start, timer_end, sleep_latency;

/**
 * @brief Handle SIGINT signal
 *
 * @param sig The signal number
 */
void handle_sigint(int sig) 
{
    (void)sig;
    keep_running = 0;
}

int main(int argc, char *argv[]) 
{
    (void)argc;
    (void)argv;
    log_set_level(LOG_LEVEL_DEBUG);
    // manager to handle creation and destruction of application code
    PluginManager *pm = plugin_manager_create("./libplc.so");

    // --- Set RT priority before PLC starts ---
    set_realtime_priority();

    cycle_max = 0;
    cycle_min = LONG_MAX;
    cycle_total = 0;
    latency_max = 0;
    latency_min = LONG_MAX;
    latency_total = 0;

    // gets the starting point for the clock
    log_info("Getting current time");
    clock_gettime(CLOCK_MONOTONIC, &timer_start);

    tzset();
    time(&start_time);

    // Event-driven: only load when a request comes
    char input[16];
    // Run PLC loop
    while (keep_running) 
    {
        printf("Type 'req' to trigger APP import: ");
        if (!fgets(input, sizeof(input), stdin))
        {
            break;
        }

        if (strncmp(input, "req", 3) == 0) 
        {
            // initializing dlsym and getting pointers to external functions
            log_info("Initializing app object");
            if (plugin_manager_load(pm)) 
            {
                pthread_t wd_thread;
                pthread_create(&wd_thread, NULL, watchdog_thread, NULL);

                log_debug("Initializing symbols");
                symbols_init(pm);

                log_debug("Initializing PLC");
                ext_config_init__();
                ext_glueVars();

                    log_info("Starting main loop");
                    while(1)
                    {
                        // Update Watchdog Heartbeat
                        atomic_store(&plc_heartbeat, time(NULL));
                
                        // Initialize timer_start once before the main loop (if not already done)
                        // clock_gettime(CLOCK_MONOTONIC, &timer_start);

                        // Get the start time for the running cycle
                        clock_gettime(CLOCK_MONOTONIC, &cycle_start);
                        ext_config_run__(tick__++);
                        ext_updateTime();

                        // Get the end time for the running cycle
                        clock_gettime(CLOCK_MONOTONIC, &cycle_end);

                        if (bool_output[0][0]) 
                        {
                            log_debug("bool_output[0][0]: %d", *bool_output[0][0]);
                        } 
                        else 
                        {
                            log_debug("bool_output[0][0] is NULL");
                            log_debug("int_output[0] is NULL");
                            log_debug("dint_memory[0] is NULL");
                            log_debug("lint_memory[0] is NULL");
                        }

                        // Compute the cycle execution time
                        timespec_diff(&cycle_end, &cycle_start, &cycle_time);
                        long cycle_time_ns = cycle_time.tv_sec * 1000000000L + cycle_time.tv_nsec;

                        if (cycle_time_ns > cycle_max)
                        {
                            cycle_max = cycle_time_ns;
                        }
                        if (cycle_time_ns < cycle_min || cycle_min == 0)  // Initialize cycle_min properly
                        {
                            cycle_min = cycle_time_ns;
                        }
                        cycle_total = cycle_total + cycle_time_ns;

                        // Calculate when the next cycle should start
                        struct timespec next_cycle_start = timer_start;
                        next_cycle_start.tv_nsec += (unsigned long long)*ext_common_ticktime__;
                        normalize_timespec(&next_cycle_start);

                        // Sleep until the next cycle should start
                        sleep_until(&timer_start, (unsigned long long)*ext_common_ticktime__);

                        // Get the actual wake-up time
                        clock_gettime(CLOCK_MONOTONIC, &timer_end);

                        // Calculate latency (difference between intended wake-up and actual wake-up)
                        timespec_diff(&timer_end, &next_cycle_start, &sleep_latency);
                        long latency_ns = sleep_latency.tv_sec * 1000000000L + sleep_latency.tv_nsec;

                        // Handle negative latency (woke up early - shouldn't happen with proper sleep_until)
                        if (latency_ns < 0)
                        {
                            latency_ns = -latency_ns;
                        }

                        if (latency_ns > latency_max)
                        {
                            latency_max = latency_ns;
                        }
                        if (latency_ns < latency_min || latency_min == 0)  // Initialize latency_min properly
                        {
                            latency_min = latency_ns;
                        }
                        latency_total = latency_total + latency_ns;

                        // Update timer_start for the next cycle
                        timer_start = timer_end;

                        // Compute/print the max/min/avg cycle time and latency
                        cycle_avg = (long)cycle_total / tick__;
                        latency_avg = (long)latency_total / tick__;

                        // Print in microseconds for better precision
                        log_debug("current/maximum/minimum/average cycle time | %ld/%ld/%ld/%ld | in μs",
                            cycle_time_ns / 1000, cycle_max / 1000, cycle_min / 1000, cycle_avg / 1000);
                        log_debug("current/maximum/minimum/average latency | %ld/%ld/%ld/%ld | in μs",
                            latency_ns / 1000, latency_max / 1000, latency_min / 1000, latency_avg / 1000);
                    }
                }
                else
                {
                    log_error("Failed to load application!!!!");
                    sleep(1);
                    continue;
                }
            }
        }

    plugin_manager_destroy(pm);
    return 0;
}
