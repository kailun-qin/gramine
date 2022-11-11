/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Kailun Qin <kailun.qin@intel.com>
 */

#include "libos_table.h"

long libos_syscall_capget(cap_user_header_t hdrp, cap_user_data_t datap) {
    if (hdrp) {
        hdrp->version = _LINUX_CAPABILITY_VERSION_3;
    }
    if (datap) {
        datap->effective = 1<<CAP_CHOWN | 1<<CAP_DAC_OVERRIDE | 1<<CAP_FOWNER | 1<<CAP_FSETID |   \
                           1<<CAP_KILL | 1<<CAP_SETGID | 1<<CAP_SETUID | 1<<CAP_SETPCAP |         \
                           1<<CAP_NET_BIND_SERVICE | 1<<CAP_NET_ADMIN | 1<<CAP_NET_RAW |          \
                           1<<CAP_SYS_CHROOT | 1<<CAP_SYS_NICE | 1<<CAP_SYS_TIME | 1<<CAP_MKNOD | \
                           1<<CAP_AUDIT_WRITE | 1<<CAP_SETFCAP;
        datap->permitted = 1<<CAP_CHOWN | 1<<CAP_DAC_OVERRIDE | 1<<CAP_FOWNER | 1<<CAP_FSETID |   \
                           1<<CAP_KILL | 1<<CAP_SETGID | 1<<CAP_SETUID | 1<<CAP_SETPCAP |         \
                           1<<CAP_NET_BIND_SERVICE | 1<<CAP_NET_ADMIN | 1<<CAP_NET_RAW |          \
                           1<<CAP_SYS_CHROOT | 1<<CAP_SYS_NICE | 1<<CAP_SYS_TIME | 1<<CAP_MKNOD | \
                           1<<CAP_AUDIT_WRITE | 1<<CAP_SETFCAP;
        datap->inheritable = 0;
    }

    /* currently just a no-op */
    return 0;
}

long libos_syscall_capset(cap_user_header_t hdrp, const cap_user_data_t datap) {
    __UNUSED(hdrp);
    __UNUSED(datap);

    /* currently just a no-op */
    return 0;
}
