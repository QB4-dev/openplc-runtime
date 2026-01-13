/**
 * @file s7comm_plugin.cpp
 * @brief S7Comm Plugin Implementation for OpenPLC Runtime v4
 *
 * This plugin implements a Siemens S7 communication server using the Snap7 library.
 * It allows S7-compatible HMIs and SCADA systems to read/write OpenPLC I/O buffers.
 *
 * Phase 1 Implementation:
 * - Basic server lifecycle (init, start, stop, cleanup)
 * - Hardcoded configuration for testing
 * - Data area registration and synchronization
 * - Event logging for connections
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pthread.h>

/* Snap7 includes */
#include "snap7_libmain.h"
#include "s7_types.h"

/* Plugin includes */
extern "C" {
#include "plugin_logger.h"
#include "plugin_types.h"
#include "s7comm_plugin.h"
}

/*
 * =============================================================================
 * Configuration Constants (Phase 1 - hardcoded)
 * These will be moved to JSON configuration in Phase 2
 * =============================================================================
 */
#define S7COMM_DEFAULT_PORT         102
#define S7COMM_DEFAULT_MAX_CLIENTS  32
#define S7COMM_BUFFER_SIZE          1024

/* Data block numbers for mapping (user-friendly numbers for Phase 1) */
#define DB_BOOL_INPUT    1      /* Maps to bool_input - %IX */
#define DB_BOOL_OUTPUT   2      /* Maps to bool_output - %QX */
#define DB_INT_INPUT     10     /* Maps to int_input - %IW */
#define DB_INT_OUTPUT    20     /* Maps to int_output - %QW */
#define DB_INT_MEMORY    100    /* Maps to int_memory - %MW */
#define DB_DINT_MEMORY   200    /* Maps to dint_memory - %MD */

/* Size of each DB in bytes */
#define DB_BOOL_SIZE     128    /* 1024 bits = 128 bytes */
#define DB_INT_SIZE      2048   /* 1024 words = 2048 bytes */
#define DB_DINT_SIZE     4096   /* 1024 dwords = 4096 bytes */

/*
 * =============================================================================
 * Plugin State
 * =============================================================================
 */
static plugin_logger_t g_logger;
static plugin_runtime_args_t g_runtime_args;
static bool g_initialized = false;
static bool g_running = false;

/* Snap7 server handle (S7Object is uintptr_t, use 0 for null) */
static S7Object g_server = 0;

/* Data buffers for S7 areas (registered with Snap7) */
static uint8_t g_db_bool_input[DB_BOOL_SIZE];
static uint8_t g_db_bool_output[DB_BOOL_SIZE];
static uint8_t g_db_int_input[DB_INT_SIZE];
static uint8_t g_db_int_output[DB_INT_SIZE];
static uint8_t g_db_int_memory[DB_INT_SIZE];
static uint8_t g_db_dint_memory[DB_DINT_SIZE];

/* System area buffers */
static uint8_t g_pe_area[DB_BOOL_SIZE];  /* Process inputs (I area) */
static uint8_t g_pa_area[DB_BOOL_SIZE];  /* Process outputs (Q area) */
static uint8_t g_mk_area[256];           /* Markers (M area) */

/*
 * =============================================================================
 * Forward Declarations
 * =============================================================================
 */
static void s7comm_event_callback(void *usrPtr, PSrvEvent PEvent, int Size);
static void sync_openplc_to_s7(void);
static void sync_s7_to_openplc(void);

/*
 * =============================================================================
 * Endianness Conversion Helpers
 * S7 protocol uses big-endian (network byte order)
 * =============================================================================
 */
static inline uint16_t swap16(uint16_t val)
{
    return ((val & 0xFF00) >> 8) | ((val & 0x00FF) << 8);
}

static inline uint32_t swap32(uint32_t val)
{
    return ((val & 0xFF000000) >> 24) |
           ((val & 0x00FF0000) >> 8)  |
           ((val & 0x0000FF00) << 8)  |
           ((val & 0x000000FF) << 24);
}

/*
 * =============================================================================
 * Plugin Lifecycle Functions
 * =============================================================================
 */

/**
 * @brief Initialize the S7Comm plugin
 */
extern "C" int init(void *args)
{
    /* Initialize logger first (before we have runtime_args) */
    plugin_logger_init(&g_logger, "S7COMM", NULL);
    plugin_logger_info(&g_logger, "Initializing S7Comm plugin...");

    if (!args) {
        plugin_logger_error(&g_logger, "init args is NULL");
        return -1;
    }

    /* Copy runtime args (critical - pointer is freed after init returns) */
    memcpy(&g_runtime_args, args, sizeof(plugin_runtime_args_t));

    /* Re-initialize logger with runtime_args for central logging */
    plugin_logger_init(&g_logger, "S7COMM", args);

    plugin_logger_info(&g_logger, "Buffer size: %d", g_runtime_args.buffer_size);
    plugin_logger_info(&g_logger, "Config path: %s",
                       g_runtime_args.plugin_specific_config_file_path);

    /* Clear all data buffers */
    memset(g_db_bool_input, 0, sizeof(g_db_bool_input));
    memset(g_db_bool_output, 0, sizeof(g_db_bool_output));
    memset(g_db_int_input, 0, sizeof(g_db_int_input));
    memset(g_db_int_output, 0, sizeof(g_db_int_output));
    memset(g_db_int_memory, 0, sizeof(g_db_int_memory));
    memset(g_db_dint_memory, 0, sizeof(g_db_dint_memory));
    memset(g_pe_area, 0, sizeof(g_pe_area));
    memset(g_pa_area, 0, sizeof(g_pa_area));
    memset(g_mk_area, 0, sizeof(g_mk_area));

    /* Create Snap7 server */
    g_server = Srv_Create();
    if (g_server == 0) {
        plugin_logger_error(&g_logger, "Failed to create Snap7 server");
        return -1;
    }

    /* Configure server parameters */
    uint16_t port = S7COMM_DEFAULT_PORT;
    int max_clients = S7COMM_DEFAULT_MAX_CLIENTS;

    Srv_SetParam(g_server, p_u16_LocalPort, &port);
    Srv_SetParam(g_server, p_i32_MaxClients, &max_clients);

    /* Set event mask to log important events */
    longword event_mask = evcServerStarted | evcServerStopped |
                          evcClientAdded | evcClientDisconnected |
                          evcClientRejected | evcListenerCannotStart;
    Srv_SetMask(g_server, mkEvent, event_mask);

    /* Set event callback for logging */
    Srv_SetEventsCallback(g_server, s7comm_event_callback, NULL);

    /* Register system areas (PE, PA, MK) */
    int result;

    result = Srv_RegisterArea(g_server, srvAreaPE, 0, g_pe_area, sizeof(g_pe_area));
    if (result != 0) {
        plugin_logger_warn(&g_logger, "Failed to register PE area: 0x%08X", result);
    }

    result = Srv_RegisterArea(g_server, srvAreaPA, 0, g_pa_area, sizeof(g_pa_area));
    if (result != 0) {
        plugin_logger_warn(&g_logger, "Failed to register PA area: 0x%08X", result);
    }

    result = Srv_RegisterArea(g_server, srvAreaMK, 0, g_mk_area, sizeof(g_mk_area));
    if (result != 0) {
        plugin_logger_warn(&g_logger, "Failed to register MK area: 0x%08X", result);
    }

    /* Register data blocks */
    result = Srv_RegisterArea(g_server, srvAreaDB, DB_BOOL_INPUT,
                              g_db_bool_input, sizeof(g_db_bool_input));
    if (result != 0) {
        plugin_logger_warn(&g_logger, "Failed to register DB%d: 0x%08X", DB_BOOL_INPUT, result);
    }

    result = Srv_RegisterArea(g_server, srvAreaDB, DB_BOOL_OUTPUT,
                              g_db_bool_output, sizeof(g_db_bool_output));
    if (result != 0) {
        plugin_logger_warn(&g_logger, "Failed to register DB%d: 0x%08X", DB_BOOL_OUTPUT, result);
    }

    result = Srv_RegisterArea(g_server, srvAreaDB, DB_INT_INPUT,
                              g_db_int_input, sizeof(g_db_int_input));
    if (result != 0) {
        plugin_logger_warn(&g_logger, "Failed to register DB%d: 0x%08X", DB_INT_INPUT, result);
    }

    result = Srv_RegisterArea(g_server, srvAreaDB, DB_INT_OUTPUT,
                              g_db_int_output, sizeof(g_db_int_output));
    if (result != 0) {
        plugin_logger_warn(&g_logger, "Failed to register DB%d: 0x%08X", DB_INT_OUTPUT, result);
    }

    result = Srv_RegisterArea(g_server, srvAreaDB, DB_INT_MEMORY,
                              g_db_int_memory, sizeof(g_db_int_memory));
    if (result != 0) {
        plugin_logger_warn(&g_logger, "Failed to register DB%d: 0x%08X", DB_INT_MEMORY, result);
    }

    result = Srv_RegisterArea(g_server, srvAreaDB, DB_DINT_MEMORY,
                              g_db_dint_memory, sizeof(g_db_dint_memory));
    if (result != 0) {
        plugin_logger_warn(&g_logger, "Failed to register DB%d: 0x%08X", DB_DINT_MEMORY, result);
    }

    g_initialized = true;
    plugin_logger_info(&g_logger, "S7Comm plugin initialized successfully");
    plugin_logger_info(&g_logger, "Registered areas: PE, PA, MK, DB%d, DB%d, DB%d, DB%d, DB%d, DB%d",
                       DB_BOOL_INPUT, DB_BOOL_OUTPUT, DB_INT_INPUT,
                       DB_INT_OUTPUT, DB_INT_MEMORY, DB_DINT_MEMORY);

    return 0;
}

/**
 * @brief Start the S7 server
 */
extern "C" void start_loop(void)
{
    if (!g_initialized) {
        plugin_logger_error(&g_logger, "Cannot start - plugin not initialized");
        return;
    }

    if (g_running) {
        plugin_logger_warn(&g_logger, "Server already running");
        return;
    }

    plugin_logger_info(&g_logger, "Starting S7 server on port %d...", S7COMM_DEFAULT_PORT);

    /* Start the server - listens on all interfaces */
    int result = Srv_Start(g_server);
    if (result != 0) {
        plugin_logger_error(&g_logger, "Failed to start S7 server: 0x%08X", result);
        plugin_logger_error(&g_logger, "Note: Port 102 requires root privileges on Linux");
        return;
    }

    g_running = true;
    plugin_logger_info(&g_logger, "S7 server started successfully");
}

/**
 * @brief Stop the S7 server
 */
extern "C" void stop_loop(void)
{
    if (!g_running) {
        plugin_logger_info(&g_logger, "Server already stopped");
        return;
    }

    plugin_logger_info(&g_logger, "Stopping S7 server...");

    Srv_Stop(g_server);
    g_running = false;

    plugin_logger_info(&g_logger, "S7 server stopped");
}

/**
 * @brief Cleanup plugin resources
 */
extern "C" void cleanup(void)
{
    plugin_logger_info(&g_logger, "Cleaning up S7Comm plugin...");

    if (g_running) {
        stop_loop();
    }

    if (g_server != 0) {
        Srv_Destroy(g_server);
        g_server = 0;
    }

    g_initialized = false;
    plugin_logger_info(&g_logger, "S7Comm plugin cleanup complete");
}

/**
 * @brief Called at the start of each PLC scan cycle
 *
 * Synchronizes OpenPLC input buffers to S7 data areas.
 * Called with buffer mutex already held by PLC cycle manager.
 */
extern "C" void cycle_start(void)
{
    if (!g_initialized || !g_running) {
        return;
    }

    /* Sync OpenPLC inputs to S7 buffers */
    sync_openplc_to_s7();
}

/**
 * @brief Called at the end of each PLC scan cycle
 *
 * Synchronizes S7 data areas to OpenPLC output buffers.
 * Called with buffer mutex already held by PLC cycle manager.
 */
extern "C" void cycle_end(void)
{
    if (!g_initialized || !g_running) {
        return;
    }

    /* Sync S7 buffers to OpenPLC outputs */
    sync_s7_to_openplc();
}

/*
 * =============================================================================
 * Snap7 Callbacks
 * =============================================================================
 */

/**
 * @brief Snap7 event callback for logging connections and errors
 */
static void s7comm_event_callback(void *usrPtr, PSrvEvent PEvent, int Size)
{
    (void)usrPtr;
    (void)Size;

    switch (PEvent->EvtCode) {
        case evcServerStarted:
            plugin_logger_info(&g_logger, "S7 server started");
            break;
        case evcServerStopped:
            plugin_logger_info(&g_logger, "S7 server stopped");
            break;
        case evcClientAdded:
            plugin_logger_info(&g_logger, "Client connected (ID: %d)", PEvent->EvtSender);
            break;
        case evcClientDisconnected:
            plugin_logger_info(&g_logger, "Client disconnected (ID: %d)", PEvent->EvtSender);
            break;
        case evcClientRejected:
            plugin_logger_warn(&g_logger, "Client rejected (ID: %d)", PEvent->EvtSender);
            break;
        case evcListenerCannotStart:
            plugin_logger_error(&g_logger, "Listener cannot start - port may be in use or requires root");
            break;
        default:
            /* Ignore other events */
            break;
    }
}

/*
 * =============================================================================
 * Buffer Synchronization Functions
 * =============================================================================
 */

/**
 * @brief Sync OpenPLC buffers to S7 data areas
 *
 * Copies current OpenPLC input/output/memory values to S7 buffers
 * so S7 clients can read them.
 */
static void sync_openplc_to_s7(void)
{
    int i, byte_idx, bit_idx;
    uint8_t byte_val;

    /* Sync bool_input to PE area and DB1 */
    for (byte_idx = 0; byte_idx < DB_BOOL_SIZE && byte_idx < g_runtime_args.buffer_size; byte_idx++) {
        byte_val = 0;
        for (bit_idx = 0; bit_idx < 8; bit_idx++) {
            IEC_BOOL *ptr = g_runtime_args.bool_input[byte_idx][bit_idx];
            if (ptr != NULL && *ptr) {
                byte_val |= (1 << bit_idx);
            }
        }
        g_pe_area[byte_idx] = byte_val;
        g_db_bool_input[byte_idx] = byte_val;
    }

    /* Sync bool_output to PA area and DB2 */
    for (byte_idx = 0; byte_idx < DB_BOOL_SIZE && byte_idx < g_runtime_args.buffer_size; byte_idx++) {
        byte_val = 0;
        for (bit_idx = 0; bit_idx < 8; bit_idx++) {
            IEC_BOOL *ptr = g_runtime_args.bool_output[byte_idx][bit_idx];
            if (ptr != NULL && *ptr) {
                byte_val |= (1 << bit_idx);
            }
        }
        g_pa_area[byte_idx] = byte_val;
        g_db_bool_output[byte_idx] = byte_val;
    }

    /* Sync int_input to DB10 (with big-endian conversion) */
    uint16_t *db_int_input = (uint16_t *)g_db_int_input;
    for (i = 0; i < S7COMM_BUFFER_SIZE && i < g_runtime_args.buffer_size; i++) {
        IEC_UINT *ptr = g_runtime_args.int_input[i];
        if (ptr != NULL) {
            db_int_input[i] = swap16(*ptr);
        }
    }

    /* Sync int_output to DB20 (with big-endian conversion) */
    uint16_t *db_int_output = (uint16_t *)g_db_int_output;
    for (i = 0; i < S7COMM_BUFFER_SIZE && i < g_runtime_args.buffer_size; i++) {
        IEC_UINT *ptr = g_runtime_args.int_output[i];
        if (ptr != NULL) {
            db_int_output[i] = swap16(*ptr);
        }
    }

    /* Sync int_memory to DB100 (with big-endian conversion) */
    uint16_t *db_int_memory = (uint16_t *)g_db_int_memory;
    for (i = 0; i < S7COMM_BUFFER_SIZE && i < g_runtime_args.buffer_size; i++) {
        IEC_UINT *ptr = g_runtime_args.int_memory[i];
        if (ptr != NULL) {
            db_int_memory[i] = swap16(*ptr);
        }
    }

    /* Sync dint_memory to DB200 (with big-endian conversion) */
    uint32_t *db_dint_memory = (uint32_t *)g_db_dint_memory;
    for (i = 0; i < S7COMM_BUFFER_SIZE && i < g_runtime_args.buffer_size; i++) {
        IEC_UDINT *ptr = g_runtime_args.dint_memory[i];
        if (ptr != NULL) {
            db_dint_memory[i] = swap32(*ptr);
        }
    }
}

/**
 * @brief Sync S7 data areas to OpenPLC buffers
 *
 * Copies values written by S7 clients back to OpenPLC output/memory buffers.
 */
static void sync_s7_to_openplc(void)
{
    int i, byte_idx, bit_idx;
    uint8_t byte_val;

    /* Sync PA area and DB2 to bool_output */
    for (byte_idx = 0; byte_idx < DB_BOOL_SIZE && byte_idx < g_runtime_args.buffer_size; byte_idx++) {
        byte_val = g_db_bool_output[byte_idx];
        for (bit_idx = 0; bit_idx < 8; bit_idx++) {
            IEC_BOOL *ptr = g_runtime_args.bool_output[byte_idx][bit_idx];
            if (ptr != NULL) {
                *ptr = (byte_val >> bit_idx) & 0x01;
            }
        }
    }

    /* Sync DB20 to int_output (with big-endian conversion) */
    uint16_t *db_int_output = (uint16_t *)g_db_int_output;
    for (i = 0; i < S7COMM_BUFFER_SIZE && i < g_runtime_args.buffer_size; i++) {
        IEC_UINT *ptr = g_runtime_args.int_output[i];
        if (ptr != NULL) {
            *ptr = swap16(db_int_output[i]);
        }
    }

    /* Sync DB100 to int_memory (with big-endian conversion) */
    uint16_t *db_int_memory = (uint16_t *)g_db_int_memory;
    for (i = 0; i < S7COMM_BUFFER_SIZE && i < g_runtime_args.buffer_size; i++) {
        IEC_UINT *ptr = g_runtime_args.int_memory[i];
        if (ptr != NULL) {
            *ptr = swap16(db_int_memory[i]);
        }
    }

    /* Sync DB200 to dint_memory (with big-endian conversion) */
    uint32_t *db_dint_memory = (uint32_t *)g_db_dint_memory;
    for (i = 0; i < S7COMM_BUFFER_SIZE && i < g_runtime_args.buffer_size; i++) {
        IEC_UDINT *ptr = g_runtime_args.dint_memory[i];
        if (ptr != NULL) {
            *ptr = swap32(db_dint_memory[i]);
        }
    }
}
