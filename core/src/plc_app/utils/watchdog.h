#ifndef WATCHDOG_H
#define WATCHDOG_H

/**
 * @brief Watchdog thread function
 *
 * @return void*
 */
void *watchdog_thread(void *);

/**
 * @brief Initialize the watchdog
 * @return int 0 on success, -1 on failure
 */
int watchdog_init();


#endif // WATCHDOG_H