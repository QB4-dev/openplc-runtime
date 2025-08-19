#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <time.h>
#ifdef __APPLE__
#include <mach/mach_time.h>
#endif
#include <signal.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>

#include "log.h"
#include "utils/utils.h"
#include "image_tables.h"

//#include <sched.h>

//struct sched_param param;

//param.sched_priority = 20;
//if (sched_setscheduler(0, SCHED_FIFO, &param) != 0) {
//    perror("sched_setscheduler");
//}

extern void* watchdog_thread(void*);
atomic_long plc_heartbeat = 0;
volatile sig_atomic_t keep_running = 1;
time_t start_time, end_time;

void (*ext_setBufferPointers)(IEC_BOOL *input_bool[BUFFER_SIZE][8], IEC_BOOL *output_bool[BUFFER_SIZE][8],
                              IEC_BYTE *input_byte[BUFFER_SIZE], IEC_BYTE *output_byte[BUFFER_SIZE],
                              IEC_UINT *input_int[BUFFER_SIZE], IEC_UINT *output_int[BUFFER_SIZE],
                              IEC_UDINT *input_dint[BUFFER_SIZE], IEC_UDINT *output_dint[BUFFER_SIZE],
                              IEC_ULINT *input_lint[BUFFER_SIZE], IEC_ULINT *output_lint[BUFFER_SIZE],
                              IEC_UINT *int_memory[BUFFER_SIZE], IEC_UDINT *dint_memory[BUFFER_SIZE], IEC_ULINT *lint_memory[BUFFER_SIZE]);

void handle_sigint(int sig) {
    (void) sig;
    keep_running = 0;
}

int main(int argc, char* argv[])
{
    (void) argc;
    (void) argv;
    log_set_level(LOG_LEVEL_DEBUG);

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

    pthread_t wd_thread;
    pthread_create(&wd_thread, NULL, watchdog_thread, NULL);

    //gets the starting point for the clock
    log_info("Getting current time");
    clock_gettime(CLOCK_MONOTONIC, &timer_start);

    // initializing dlsym and getting pointers to external functions
    log_info("Initializing symbols");
    symbols_init();

    // Send buffer pointers to .so
    ext_setBufferPointers(bool_input, bool_output,
                          byte_input, byte_output,
                          int_input, int_output,
                          dint_input, dint_output,
                          lint_input, lint_output,
                          int_memory, dint_memory, lint_memory);
    
    tzset();
    time(&start_time);

    // Init PLC
    ext_config_init__();
    ext_glueVars();

    // Run PLC loop
    while (keep_running)
    {
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

        if (bool_output[0][0])
        {
            log_debug("bool_output[0][0]: %d", *bool_output[0][0]);
            // log_debug("int_output[0]: %d", *int_output[0]);
            // log_debug("dint_output[0]: %ld", *dint_memory[0]);
            // log_debug("lint_output[0]: %lld", *lint_memory[0]);

            // if (bool_output[0][0] && int_output[0] && dint_memory[0] && lint_memory[0])
            // {
            //     log_info("int_input[0]: %d | bool_input[0][1]: %d", 
            //         *int_input[0], *bool_input[0][1]);
            //     *int_input[0] += 1;
            //     log_info("PLC running with tick: %lu", tick__);
            // }
            // else
            // {
            //     log_error("One or more output pointers are NULL");
            // }
            
            // if (*int_output[0] >= 10)
            // {
            //     *bool_input[0][0] = 1;
            //     log_info("reset bool_input[0][0]");
            // }
            // else{
            //     *bool_input[0][0] = 0;
            //     log_info("reset bool_input[0][0]");
            // }
        }
        else
        {
            log_debug("bool_output[0][0] is NULL");
            log_debug("int_output[0] is NULL");
            log_debug("dint_memory[0] is NULL");
            log_debug("lint_memory[0] is NULL");
        }

        // printf("%d\n", *ext_common_ticktime__);

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
