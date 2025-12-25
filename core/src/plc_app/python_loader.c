//-----------------------------------------------------------------------------
// Copyright 2025 Thiago Alves
// This file is part of the OpenPLC Runtime.
//
// OpenPLC is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// OpenPLC is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with OpenPLC.  If not, see <http://www.gnu.org/licenses/>.
//------
//
// This file is responsible for loading function blocks written in Python.
// Python function blocks communicate with the PLC runtime via shared memory.
//
// Logging is done via function pointers that are set by the runtime after
// loading libplc.so. This avoids symbol resolution issues between the
// shared library and the main executable.
//
// Thiago Alves, Dec 2025
//-----------------------------------------------------------------------------

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "include/iec_python.h"

// Function pointers for logging - set by python_loader_set_loggers()
// These are always initialized by symbols_init() before any Python FB code runs
static void (*py_log_info)(const char *fmt, ...);
static void (*py_log_error)(const char *fmt, ...);

// Simple wrapper macros for logging
#define LOG_INFO(...) py_log_info(__VA_ARGS__)
#define LOG_ERROR(...) py_log_error(__VA_ARGS__)

void python_loader_set_loggers(void (*log_info_func)(const char *, ...),
                               void (*log_error_func)(const char *, ...))
{
    py_log_info  = log_info_func;
    py_log_error = log_error_func;
}

/**
 * @brief Thread function that runs the Python script and logs its output
 *
 * This function is spawned as a detached thread to run the Python interpreter
 * and capture its stdout/stderr output for logging.
 *
 * @param arg The command string to execute (will be freed by this function)
 * @return NULL
 */
static void *runner_thread(void *arg)
{
    const char *cmd = (const char *)arg;
    FILE *fp        = popen(cmd, "r");
    if (fp == NULL)
    {
        LOG_ERROR("[Python] Failed to start process: %s", cmd);
        free((void *)cmd);
        return NULL;
    }

    char buffer[512];
    while (fgets(buffer, sizeof(buffer), fp) != NULL)
    {
        // Remove trailing newline if present
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len - 1] == '\n')
        {
            buffer[len - 1] = '\0';
        }
        LOG_INFO("[Python] %s", buffer);
    }

    pclose(fp);
    free((void *)cmd);
    return NULL;
}

int create_shm_name(char *buf, size_t size)
{
    char shm_mask[] = "/tmp/shmXXXXXXXXXXXX";
    int fd          = mkstemp(shm_mask);
    if (fd == -1)
    {
        LOG_ERROR("[Python loader] mkstemp failed: %s", strerror(errno));
        return -1;
    }
    close(fd);

    snprintf(buf, size, "/%s", strrchr(shm_mask, '/') + 1);
    unlink(shm_mask);

    return 0;
}

int python_block_loader(const char *script_name, const char *script_content, char *shm_name,
                        size_t shm_in_size, size_t shm_out_size, void **shm_in_ptr,
                        void **shm_out_ptr, pid_t pid)
{
    char shm_in_name[256];
    char shm_out_name[256];

    // Write the Python script to disk
    FILE *fp = fopen(script_name, "w");
    if (!fp)
    {
        LOG_ERROR("[Python loader] Failed to write Python script: %s", strerror(errno));
        return -1;
    }
    chmod(script_name, 0640);

    LOG_INFO("[Python loader] Random shared memory location: %s", shm_name);

    snprintf(shm_in_name, sizeof(shm_in_name), "%s_in", shm_name);
    snprintf(shm_out_name, sizeof(shm_out_name), "%s_out", shm_name);

    // Write script content with format specifiers replaced
    fprintf(fp, script_content, pid, shm_name, shm_name);
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);

    // Map shared memory for inputs
    int shm_in_fd = shm_open(shm_in_name, O_CREAT | O_RDWR, 0660);
    if (shm_in_fd < 0)
    {
        LOG_ERROR("[Python loader] shm_open (input) error: %s", strerror(errno));
        return -1;
    }
    if (ftruncate(shm_in_fd, shm_in_size) == -1)
    {
        LOG_ERROR("[Python loader] ftruncate (input) error: %s", strerror(errno));
        close(shm_in_fd);
        return -1;
    }
    *shm_in_ptr = mmap(NULL, shm_in_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_in_fd, 0);
    if (*shm_in_ptr == MAP_FAILED)
    {
        LOG_ERROR("[Python loader] mmap (input) error: %s", strerror(errno));
        close(shm_in_fd);
        return -1;
    }

    // Map shared memory for outputs
    int shm_out_fd = shm_open(shm_out_name, O_CREAT | O_RDWR, 0660);
    if (shm_out_fd < 0)
    {
        LOG_ERROR("[Python loader] shm_open (output) error: %s", strerror(errno));
        close(shm_in_fd);
        munmap(*shm_in_ptr, shm_in_size);
        shm_unlink(shm_in_name);
        return -1;
    }
    if (ftruncate(shm_out_fd, shm_out_size) == -1)
    {
        LOG_ERROR("[Python loader] ftruncate (output) error: %s", strerror(errno));
        close(shm_out_fd);
        close(shm_in_fd);
        munmap(*shm_in_ptr, shm_in_size);
        shm_unlink(shm_in_name);
        return -1;
    }
    *shm_out_ptr = mmap(NULL, shm_out_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_out_fd, 0);
    if (*shm_out_ptr == MAP_FAILED)
    {
        LOG_ERROR("[Python loader] mmap (output) error: %s", strerror(errno));
        close(shm_out_fd);
        close(shm_in_fd);
        munmap(*shm_in_ptr, shm_in_size);
        shm_unlink(shm_in_name);
        return -1;
    }

    // Close file descriptors (mapping remains valid)
    close(shm_in_fd);
    close(shm_out_fd);

    // Prepare command to run Python script
    char *cmd = malloc(512);
    if (cmd == NULL)
    {
        LOG_ERROR("[Python loader] malloc failed for cmd buffer");
        return -1;
    }
    snprintf(cmd, 512, "python3 -u %s 2>&1", script_name);

    // Spawn thread to run Python process
    pthread_t tid;
    if (pthread_create(&tid, NULL, runner_thread, cmd) != 0)
    {
        LOG_ERROR("[Python loader] pthread_create failed: %s", strerror(errno));
        free(cmd);
        return -1;
    }
    pthread_detach(tid);

    LOG_INFO("[Python loader] Started Python function block: %s", script_name);

    return 0;
}
