#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <assert.h>
#include <pthread.h>
#include <unistd.h>

#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

#pragma GCC push_options
#pragma GCC optimize("O0")

void*
os_thread(void*)
{
    sleep(10000);
    return NULL;
}

pthread_t
start_os_thread()
{
    pthread_t thread;
    int ret = pthread_create(&thread, NULL, &os_thread, NULL);
    assert(0 == ret);
    (void)ret;  // Suppress unused variable warning

    return thread;
}

void
cancel_os_thread(pthread_t tid)
{
    pthread_join(tid, NULL);
}

void*
sleepThread(void*)
{
#ifdef __APPLE__
    // On macOS, pthread_setname_np only takes the name and sets current thread
    pthread_setname_np("thread_foo");
#endif
    PyGILState_STATE gilstate = PyGILState_Ensure();
    sleep(1000);
    PyGILState_Release(gilstate);
    return NULL;
}

PyObject*
sleep10(PyObject*, PyObject*)
{
    pthread_t thread;
    int ret = pthread_create(&thread, NULL, &sleepThread, NULL);
    assert(0 == ret);
    pthread_t tid = start_os_thread();
#ifndef __APPLE__
    // On Linux, we can set another thread's name
    pthread_setname_np(thread, "thread_foo");
#endif
    // On macOS, the thread sets its own name in sleepThread()

    Py_BEGIN_ALLOW_THREADS ret = pthread_join(thread, NULL);
    Py_END_ALLOW_THREADS

            assert(0 == ret);
    cancel_os_thread(tid);
    Py_RETURN_NONE;
}

#pragma GCC pop_options

static PyMethodDef methods[] = {
        {"sleep10", sleep10, METH_NOARGS, "Sleep for 10 seconds"},
        {NULL, NULL, 0, NULL},
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef moduledef = {PyModuleDef_HEAD_INIT, "testext", "", -1, methods};

PyMODINIT_FUNC
PyInit_testext(void)
{
    PyObject* mod = PyModule_Create(&moduledef);
#    ifdef Py_GIL_DISABLED
    PyUnstable_Module_SetGIL(mod, Py_MOD_GIL_NOT_USED);
#    endif
    return mod;
}
#else
PyMODINIT_FUNC
inittestext(void)
{
    Py_InitModule("testext", methods);
}
#endif
