#ifndef IMAGE_TABLES_H
#define IMAGE_TABLES_H

#include "../lib/iec_types.h"
#include "plcapp_manager.h"

#define BUFFER_SIZE 1024
#define libplc_build_dir "./build"

// Internal buffers for I/O and memory.
// Booleans
extern IEC_BOOL *bool_input[BUFFER_SIZE][8];
extern IEC_BOOL *bool_output[BUFFER_SIZE][8];

// Bytes
extern IEC_BYTE *byte_input[BUFFER_SIZE];
extern IEC_BYTE *byte_output[BUFFER_SIZE];

// Analog I/O
extern IEC_UINT *int_input[BUFFER_SIZE];
extern IEC_UINT *int_output[BUFFER_SIZE];

// 32bit I/O
extern IEC_UDINT *dint_input[BUFFER_SIZE];
extern IEC_UDINT *dint_output[BUFFER_SIZE];

// 64bit I/O
extern IEC_ULINT *lint_input[BUFFER_SIZE];
extern IEC_ULINT *lint_output[BUFFER_SIZE];

// Memory
extern IEC_UINT *int_memory[BUFFER_SIZE];
extern IEC_UDINT *dint_memory[BUFFER_SIZE];
extern IEC_ULINT *lint_memory[BUFFER_SIZE];
extern IEC_BOOL *bool_memory[BUFFER_SIZE][8];

/**
 * @brief Set the buffer pointers for the plugin manager
 *
 * @param[in]  IEC  The IEC data types
 */
extern void (*ext_setBufferPointers)(
    IEC_BOOL *input_bool[BUFFER_SIZE][8], IEC_BOOL *output_bool[BUFFER_SIZE][8],
    IEC_BYTE *input_byte[BUFFER_SIZE], IEC_BYTE *output_byte[BUFFER_SIZE],
    IEC_UINT *input_int[BUFFER_SIZE], IEC_UINT *output_int[BUFFER_SIZE],
    IEC_UDINT *input_dint[BUFFER_SIZE], IEC_UDINT *output_dint[BUFFER_SIZE],
    IEC_ULINT *input_lint[BUFFER_SIZE], IEC_ULINT *output_lint[BUFFER_SIZE],
    IEC_UINT *int_memory[BUFFER_SIZE], IEC_UDINT *dint_memory[BUFFER_SIZE],
    IEC_ULINT *lint_memory[BUFFER_SIZE]);

/**
 * @brief Set the buffer pointers for the plugin manager (v4 with bool_memory)
 *
 * This version includes bool_memory support for %MX locations.
 * Only present in programs compiled with -DOPENPLC_V4.
 */
extern void (*ext_setBufferPointers_v4)(
    IEC_BOOL *input_bool[BUFFER_SIZE][8], IEC_BOOL *output_bool[BUFFER_SIZE][8],
    IEC_BYTE *input_byte[BUFFER_SIZE], IEC_BYTE *output_byte[BUFFER_SIZE],
    IEC_UINT *input_int[BUFFER_SIZE], IEC_UINT *output_int[BUFFER_SIZE],
    IEC_UDINT *input_dint[BUFFER_SIZE], IEC_UDINT *output_dint[BUFFER_SIZE],
    IEC_ULINT *input_lint[BUFFER_SIZE], IEC_ULINT *output_lint[BUFFER_SIZE],
    IEC_UINT *int_memory[BUFFER_SIZE], IEC_UDINT *dint_memory[BUFFER_SIZE],
    IEC_ULINT *lint_memory[BUFFER_SIZE], IEC_BOOL *memory_bool[BUFFER_SIZE][8]);

/**
 * @brief Common ticktime variable from the PLC program
 *
 * @param[in]  tick  The current tick value
 */
extern void (*ext_config_run__)(unsigned long tick);

/**
 * @brief Initialize the configuration
 */
extern void (*ext_config_init__)(void);

/**
 * @brief Glue variables together
 */
extern void (*ext_glueVars)(void);
extern void (*ext_updateTime)(void);

/**
 * @brief Debug functions
 */
extern void (*ext_set_endianness)(uint8_t value);
extern uint16_t (*ext_get_var_count)(void);
extern size_t (*ext_get_var_size)(size_t idx);
extern void *(*ext_get_var_addr)(size_t idx);
extern void (*ext_set_trace)(size_t idx, bool forced, void *val);

/**
 * @brief Initialize symbols for the plugin manager
 *
 * @param[in]  pm  The plugin manager to initialize symbols for
 * @return 0 on success, -1 on failure
 */
int symbols_init(PluginManager *pm);

/**
 * @brief Fill NULL pointers in image tables with temporary backing buffers
 *
 * This function iterates through all image table arrays and points any NULL
 * entries to temporary backing storage. This ensures that plugins accessing
 * addresses not used by the PLC program won't fail due to NULL pointer access.
 *
 * Must be called after ext_glueVars() has mapped the user program's located
 * variables to the image tables.
 *
 * @note This function should be called with buffer_mutex held for thread safety.
 */
void image_tables_fill_null_pointers(void);

/**
 * @brief Clear all pointers from image tables
 *
 * This function resets all pointers in the image tables back to NULL.
 * All pointers will be remapped when a new program is loaded via glueVars().
 *
 * Must be called before unloading a PLC program to ensure clean state for
 * the next program load.
 *
 * @note This function should be called with buffer_mutex held for thread safety.
 */
void image_tables_clear_null_pointers(void);

#endif // IMAGE_TABLES_H
