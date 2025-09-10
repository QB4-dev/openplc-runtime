#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "unix_socket.h"
#include "utils/log.h"
#include "utils/utils.h"
#include "plc_state_manager.h"

extern volatile sig_atomic_t keep_running;
extern PLCState plc_state;

// helper: read one line terminated by '\n' from a socket
static ssize_t read_line(int fd, char *buffer, size_t max_length)
{
    size_t total_read = 0;
    char ch;
    while (total_read < max_length - 1) 
    {
        ssize_t bytes_read = read(fd, &ch, 1);
        if (bytes_read <= 0) 
        {
            return bytes_read; // error or connection closed
        }
        if (ch == '\n') 
        {
            break; // end of line
        }
        buffer[total_read++] = ch;
    }
    buffer[total_read] = '\0'; // null-terminate the string
    return total_read;
}

void handle_unix_socket_commands(char *command)
{
    if (strcmp(command, "STATUS") == 0) 
    {
        log_debug("Received STATUS command");
        // TODO: Implement status reporting
    } 
    else if (strcmp(command, "STOP") == 0) 
    {
        log_debug("Received STOP command");
        set_plc_state(PLC_STATE_STOPPED);
    } 
    else if (strcmp(command, "START") == 0) 
    {
        log_debug("Received START command");
        PLCState current_state = plc_get_state();
        if (current_state == PLC_STATE_STOPPED || current_state == PLC_STATE_ERROR) 
        {
            set_plc_state(PLC_STATE_RUNNING);
        } 
        else 
        {
            log_info("PLC is already running");
        }
    }
    else 
    {
        log_error("Unknown command received: %s", command);
    }
}

void *unix_socket_thread(void *arg) 
{
    (void)arg;
    int *server_fd_pt = (int *)arg;
    int client_fd;
    char command_buffer[COMMAND_BUFFER_SIZE];

    if (server_fd_pt == NULL) 
    {
        log_error("Server file descriptor is NULL");
        return NULL;
    }
    
    int server_fd = *server_fd_pt;
    if (server_fd < 0) 
    {
        log_error("Failed to set up UNIX socket");
        return NULL;
    }

    while (keep_running)
    {
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) 
        {
            if (errno == EINTR) 
            {
                continue; // Interrupted by signal, retry
            }
            log_error("Unix socket accept failed: %s", strerror(errno));
            
            // Retry after a short delay
            sleep(1);
            continue;
        }

        log_info("Unix socket client connected");

        while (keep_running)
        {
            ssize_t bytes_read = read_line(client_fd, command_buffer, COMMAND_BUFFER_SIZE);
            if (bytes_read > 0) 
            {
                log_debug("Received command: %s", command_buffer);

                // Handle the command
                handle_unix_socket_commands(command_buffer);
            }
            else if (bytes_read == 0)
            {
                log_info("Unix socket client disconnected");
                break;
            } 
            else 
            {
                log_error("Unix socket read failed: %s", strerror(errno));
                break;
            }
        }
        close(client_fd);
    }

    close_unix_socket(server_fd);
    return NULL;
}

int setup_unix_socket()
{
    int server_fd;
    struct sockaddr_un address;

    // Remove any existing socket file
    unlink(SOCKET_PATH);

    // Create socket
    if ((server_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) 
    {
        log_error("Socket creation failed: %s", strerror(errno));
        return -1;
    }

    // Configure socket address structure
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, SOCKET_PATH, sizeof(address.sun_path) - 1);

    // Bind socket to the address
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) 
    {
        log_error("Socket bind failed: %s", strerror(errno));
        close(server_fd);
        return -1;
    }

    // Listen for incoming connections
    if (listen(server_fd, MAX_CLIENTS) < 0) 
    {
        log_error("Socket listen failed: %s", strerror(errno));
        close(server_fd);
        return -1;
    }

    log_info("UNIX socket server setup at %s", SOCKET_PATH);
    
    // Create a thread to handle socket commands
    pthread_t socket_thread;
    if (pthread_create(&socket_thread, NULL, unix_socket_thread, &server_fd) != 0) 
    {
        log_error("Failed to create UNIX socket thread: %s", strerror(errno));
        close(server_fd);
        return -1;
    }

    return 0;
}