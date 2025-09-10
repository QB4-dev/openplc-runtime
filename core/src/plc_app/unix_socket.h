#ifndef UNIX_SOCKET_H
#define UNIX_SOCKET_H

#define SOCKET_PATH "/tmp/plc_runtime.socket"
#define COMMAND_BUFFER_SIZE 1024
#define MAX_CLIENTS 1

int setup_unix_socket();
void close_unix_socket();
void handle_unix_socket_commands();
void *unix_socket_thread(void *arg);

#endif // UNIX_SOCKET_H