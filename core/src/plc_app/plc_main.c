#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <time.h>
#include <signal.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <sched.h>

#include "log.h"
#include "utils/utils.h"
#include "image_tables.h"

extern void* watchdog_thread(void*);
atomic_long plc_heartbeat = 0;
volatile sig_atomic_t keep_running = 1;
time_t start_time, end_time;

void handle_sigint(int sig) {
    (void) sig;
    keep_running = 0;
}

// Optional helper: configure SCHED_FIFO priority
static void set_realtime_priority(void) {
    struct sched_param param;
    param.sched_priority = 20;  // Priority between 1 and 99

    if (sched_setscheduler(0, SCHED_FIFO, &param) != 0) {
        fprintf(stderr,
            "sched_setscheduler failed: %s\n",
            strerror(errno));
    } else {
        printf("Scheduler set to SCHED_FIFO, priority %d\n", param.sched_priority);
    }
}

int main(int argc, char* argv[])
{
    (void) argc;
    (void) argv;
    log_set_level(LOG_LEVEL_DEBUG);

    // --- Set RT priority before PLC starts ---
    set_realtime_priority();

    // Define the max/min/avg/total cycle and latency variables used in REAL-TIME computation(in nanoseconds)
    long cycle_avg, cycle_max, cycle_min, cycle_total;
    long latency_avg, latency_max, latency_min, latency_total;
    cycle_max = 0;
    cycle_min = LONG_MAX;
    cycle_total = 0;
    latency_max = 0;
    latency_min = LONG_MAX;
    latency_total = 0;

    // Define the start, end, cycle time and latency time variables
    struct timespec cycle_start, cycle_end, cycle_time;
    struct timespec timer_start, timer_end, sleep_latency;

    //gets the starting point for the clock
    log_info("Getting current time");
    clock_gettime(CLOCK_MONOTONIC, &timer_start);

    tzset();
    time(&start_time);
    
    // Run PLC loop
    while (keep_running)
    {        
        // initializing dlsym and getting pointers to external functions
        log_info("Initializing symbols");
        if (symbols_init() != 0)
        {
            log_error("Failed to initialize symbols");
            sleep(1);
        }
        else
        {
            // create watchdog thread
            pthread_t wd_thread;
            pthread_create(&wd_thread, NULL, watchdog_thread, NULL);
        
            // Init PLC
            log_debug("Initializing PLC");
            ext_config_init__();
            ext_glueVars();
            
            log_info("Starting main loop");
            while(1)
            {
                // Update Watchdog Heartbeat
                atomic_store(&plc_heartbeat, time(NULL));
        
                // Get the start time for the running cycle
                clock_gettime(CLOCK_MONOTONIC, &cycle_start);
                
                ext_config_run__(tick__++);
                ext_updateTime();
                // Get the end time for the running cycle
                clock_gettime(CLOCK_MONOTONIC, &cycle_end);
                
                // Compute the time usage in one cycle and do max/min/total comparison/recording
                timespec_diff(&cycle_end, &cycle_start, &cycle_time);
                if (cycle_time.tv_nsec > cycle_max)
                cycle_max = cycle_time.tv_nsec;
                if (cycle_time.tv_nsec < cycle_min)
                    cycle_min = cycle_time.tv_nsec;
                cycle_total = cycle_total + cycle_time.tv_nsec;
                
                                
                // usleep((int)*ext_common_ticktime__ % 1000);
                sleep_until(&timer_start, (unsigned long long)*ext_common_ticktime__);
                
                // TODO move to utils.c
                // Get the sleep end point which is also the start time/point of the next cycle
                clock_gettime(CLOCK_MONOTONIC, &timer_end);
                // Compute the time latency of the next cycle(caused by sleep) and do max/min/total comparison/recording
                timespec_diff(&timer_end, &timer_start, &sleep_latency);
                if (sleep_latency.tv_nsec > latency_max)
                    latency_max = sleep_latency.tv_nsec;
                if (sleep_latency.tv_nsec < latency_min)
                    latency_min = sleep_latency.tv_nsec;
                latency_total = latency_total + sleep_latency.tv_nsec;
                    
                // Compute/print the max/min/avg cycle time and latency
                cycle_avg = (long)cycle_total / tick__;
                latency_avg = (long)latency_total / tick__;
                log_debug("maximum/minimum/average cycle time | %ld/%ld/%ld | in ms",
                    cycle_max / 1000, cycle_min / 1000, cycle_avg / 1000);
                log_debug("maximum/minimum/average latency | %ld/%ld/%ld | in ms",
                    latency_max / 1000,   latency_min / 1000, latency_avg / 1000);
            }
        }
    }
}
