/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This source file contains functions to create a child process and terminate the running process.
 * Child does not inherit any objects or memory from its parent process. A parent process may not
 * modify the execution of its children. It can wait for a child to exit using its handle. Also,
 * parent and child may communicate through I/O streams provided by the parent to the child at
 * creation.
 */

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"

int _PalProcessCreate(const char** args, uintptr_t (*reserved_mem_ranges)[2],
                      size_t reserved_mem_ranges_len, PAL_HANDLE* out_handle) {
    return PAL_ERROR_NOTIMPLEMENTED;
}

noreturn void _PalProcessExit(int exitcode) {
    die_or_inf_loop();
}

static int64_t proc_read(PAL_HANDLE handle, uint64_t offset, uint64_t count, void* buffer) {
    return PAL_ERROR_NOTIMPLEMENTED;
}

static int64_t proc_write(PAL_HANDLE handle, uint64_t offset, uint64_t count, const void* buffer) {
    return PAL_ERROR_NOTIMPLEMENTED;
}

static void proc_destroy(PAL_HANDLE handle) {
    /* noop */
}

struct handle_ops g_proc_ops = {
    .read  = &proc_read,
    .write = &proc_write,
    .destroy = &proc_destroy,
};
