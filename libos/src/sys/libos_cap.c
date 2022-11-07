/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Kailun Qin <kailun.qin@intel.com>
 */

#include "libos_table.h"

long libos_syscall_capget(cap_user_header_t hdrp, cap_user_data_t datap) {
    __UNUSED(hdrp);
    __UNUSED(datap);

    /* currently just a no-op */
    return 0;
}

long libos_syscall_capset(cap_user_header_t hdrp, const cap_user_data_t datap) {
    __UNUSED(hdrp);
    __UNUSED(datap);

    /* currently just a no-op */
    return 0;
}
