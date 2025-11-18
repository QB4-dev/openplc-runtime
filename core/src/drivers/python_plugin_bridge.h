#ifndef __PYTHON_PLUGIN_BRIDGE_H
#define __PYTHON_PLUGIN_BRIDGE_H

#define PY_SSIZE_T_CLEAN
#include <Python.h>

// Forward declaration
struct plugin_instance_s;

// Python plugin bridge structure
typedef struct
{
    PyObject *pModule;
    PyObject *pFuncInit; // Driver Init function
    PyObject *pFuncStart;
    PyObject *pFuncStop;
    PyObject *pFuncCleanup;
    PyObject *args_capsule; // Capsule containing plugin_runtime_args_t for lifetime management
} python_binds_t;

#endif // __PYTHON_PLUGIN_BRIDGE_H
