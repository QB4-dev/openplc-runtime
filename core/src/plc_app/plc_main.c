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
#include "utils/log.h"
#include "plcapp_manager.h"
#include "utils/utils.h"
#include "utils/watchdog.h"
#include "scan_cycle_manager.h"

extern atomic_long plc_heartbeat = 0;
extern PLCState plc_state;
volatile sig_atomic_t keep_running = 1;
struct timespec timer_start;


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

void *plc_cycle_thread(void *arg) 
{
    PluginManager *pm = (PluginManager *)arg;

    // Initialize PLC
    set_realtime_priority();
    symbols_init(pm);
    ext_config_init__();
    ext_glueVars();

    log_info("Starting main loop");
    plc_state = PLC_STATE_RUNNING;
    log_info("PLC State: RUNNING");

    while (plc_state == PLC_STATE_RUNNING)
    {
        scan_cycle_time_start();

        // Get the start time for the running cycle
        clock_gettime(CLOCK_MONOTONIC, &timer_start);

        // Execute the PLC cycle
        ext_config_run__(tick__++);
        ext_updateTime();

        // Update Watchdog Heartbeat
        atomic_store(&plc_heartbeat, time(NULL));

        scan_cycle_time_end();

        // Sleep until the next cycle should start
        sleep_until(&timer_start, (unsigned long long)*ext_common_ticktime__);
    }

    return NULL;
}

int load_plc_program(PluginManager *pm)
{
    if (plugin_manager_load(pm)) 
    {
        log_info("Loading PLC application");
        plc_state = PLC_STATE_INIT;
        log_info("PLC State: INIT");

        pthread_t plc_thread;
        if (pthread_create(&plc_thread, NULL, plc_cycle_thread, pm) != 0) 
        {
            log_error("Failed to create PLC cycle thread");
            plc_state = PLC_STATE_ERROR;
            log_info("PLC State: ERROR");
            return -1;
        }
        return 0;
    } 
    else 
    {
        log_error("Failed to load PLC application");
        plc_state = PLC_STATE_ERROR;
        log_info("PLC State: ERROR");
        return -1;
    }
}


int main(int argc, char *argv[]) 
{
    log_set_level(LOG_LEVEL_DEBUG);

    // Initialize watchdog
    if (watchdog_init() != 0)
    {
        log_error("Failed to initialize watchdog");
        return -1;
    }

    // manager to handle creation and destruction of application code
    PluginManager *pm = plugin_manager_create("./libplc.so");
    load_plc_program(pm);

    while (keep_running) 
    {
        // Handle UNIX socket here in the future
        sleep(1);
    }

    plugin_manager_destroy(pm);
    log_info("Exiting...");
    return 0;
}