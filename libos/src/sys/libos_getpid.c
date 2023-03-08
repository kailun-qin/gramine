/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "libos_lock.h"
#include "libos_process.h"
#include "libos_table.h"
#include "libos_thread.h"
#include "libos_types.h"

long libos_syscall_getpid(void) {
    return g_process.pid;
}

long libos_syscall_gettid(void) {
    /* `tid` is constant, no need to take a lock. */
    return get_cur_thread()->tid;
}

long libos_syscall_getppid(void) {
    return g_process.ppid;
}

long libos_syscall_set_tid_address(int* tidptr) {
    struct libos_thread* cur = get_cur_thread();
    lock(&cur->lock);
    cur->clear_child_tid = tidptr;
    unlock(&cur->lock);
    return cur->tid;
}

long libos_syscall_setpgid(pid_t pid, pid_t pgid) {
    if (pgid < 0) {
        return -EINVAL;
    }

    if (!pid || g_process.pid == (IDTYPE)pid) {
        lock(&g_process_id_lock);
        g_process.pgid = (IDTYPE)pgid ?: g_process.pid;
        unlock(&g_process_id_lock);

        /* TODO: inform parent about pgid change. */
        return 0;
    }

    /* TODO: Currently we do not support setting pgid of children processes. */
    return -EINVAL;
}

long libos_syscall_getpgid(pid_t pid) {
    if (!pid || g_process.pid == (IDTYPE)pid) {
        lock(&g_process_id_lock);
        long ret = g_process.pgid;
        unlock(&g_process_id_lock);

        return ret;
    }

    /* TODO: Currently we do not support getting pgid of other processes.
     * Implement child lookup once `libos_syscall_setpgid` sends info to the parent. */
    return -EINVAL;
}

long libos_syscall_getpgrp(void) {
    return libos_syscall_getpgid(0);
}

long libos_syscall_setsid(void) {
    lock(&g_process_id_lock);

    IDTYPE current_pid = g_process.pid;
    IDTYPE current_ppid = g_process.ppid;
    IDTYPE current_pgid = g_process.pgid;

    /* If the caller is already a group leader or part of a process group whose leader is the
     * caller's parent process, a new session cannot be created. */
    if (current_pid == current_pgid || current_pgid == current_ppid) {
        unlock(&g_process_id_lock);
        return -EPERM;
    }

    /* The calling process is the leader of the new session and the process group leader of the new
     * process group. */
    g_process.sid = current_pid;
    g_process.pgid = current_pid;

    unlock(&g_process_id_lock);

    return current_pid;
}

long libos_syscall_getsid(pid_t pid) {
    if (!pid || g_process.pid == (IDTYPE)pid) {
        lock(&g_process_id_lock);
        long ret = g_process.sid;
        unlock(&g_process_id_lock);

        return ret;
    }

    /* TODO: Currently we do not support getting sid of other processes. */
    return -EINVAL;
}
