#ifndef UTILS_H
#define UTILS_H

#include <time.h>

#include "./lib/iec_types.h"
#include "log.h"

#define BUFFER_SIZE		1024

//Internal buffers for I/O and memory.
//Booleans
IEC_BOOL *bool_input[BUFFER_SIZE][8];
IEC_BOOL *bool_output[BUFFER_SIZE][8];

//Bytes
IEC_BYTE *byte_input[BUFFER_SIZE];
IEC_BYTE *byte_output[BUFFER_SIZE];

//Analog I/O
IEC_UINT *int_input[BUFFER_SIZE];
IEC_UINT *int_output[BUFFER_SIZE];

//32bit I/O
IEC_UDINT *dint_input[BUFFER_SIZE];
IEC_UDINT *dint_output[BUFFER_SIZE];

//64bit I/O
IEC_ULINT *lint_input[BUFFER_SIZE];
IEC_ULINT *lint_output[BUFFER_SIZE];

//Memory
IEC_UINT *int_memory[BUFFER_SIZE];
IEC_UDINT *dint_memory[BUFFER_SIZE];
IEC_ULINT *lint_memory[BUFFER_SIZE];

//IEC_BOOL *(*ext_bool_output)[8];
extern unsigned long long *ext_common_ticktime__;
extern unsigned long tick__;

void (*ext_config_run__)(unsigned long tick);
void (*ext_config_init__)(void);
void (*ext_glueVars)(void);
void (*ext_updateTime)(void);
void (*ext_setBufferPointers)(IEC_BYTE *input_byte[BUFFER_SIZE][8], IEC_BYTE *output_byte[BUFFER_SIZE][8],
                              IEC_UINT *input_int[BUFFER_SIZE][8], IEC_UINT *output_int[BUFFER_SIZE][8],
                              IEC_UDINT *input_dint[BUFFER_SIZE][8], IEC_UDINT *output_dint[BUFFER_SIZE][8],
                              IEC_ULINT *input_lint[BUFFER_SIZE][8], IEC_ULINT *output_lint[BUFFER_SIZE][8],
                              IEC_UINT *memory_int[BUFFER_SIZE][8], IEC_UDINT *memory_dint[BUFFER_SIZE][8],
                              IEC_ULINT *memory_lint[BUFFER_SIZE][8]);
void normalize_timespec(struct timespec *ts);
void sleep_until(struct timespec *ts, long period_ns);
void timespec_diff(struct timespec *a, struct timespec *b, struct timespec *result);
void symbols_init(void);

#endif // UTILS_H
