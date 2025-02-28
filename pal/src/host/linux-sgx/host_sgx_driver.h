/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* (C) Copyright 2020 Intel Corporation
 *                    Dmitrii Kuvaiskii <dmitrii.kuvaiskii@intel.com>
 */

#pragma once

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#include <asm/ioctl.h>
#include <asm/sgx.h>
#include <linux/stddef.h>
#include <linux/types.h>

/* Gramine needs the below subset of SGX instructions' return values */
#ifndef SGX_INVALID_SIG_STRUCT
#define SGX_INVALID_SIG_STRUCT  1
#endif

#ifndef SGX_INVALID_ATTRIBUTE
#define SGX_INVALID_ATTRIBUTE   2
#endif

#ifndef SGX_INVALID_MEASUREMENT
#define SGX_INVALID_MEASUREMENT 4
#endif

#ifndef SGX_INVALID_SIGNATURE
#define SGX_INVALID_SIGNATURE   8
#endif

#ifndef SGX_INVALID_EINITTOKEN
#define SGX_INVALID_EINITTOKEN  16
#endif

#ifndef SGX_INVALID_CPUSVN
#define SGX_INVALID_CPUSVN      32
#endif

#ifndef SGX_IOC_ENCLAVE_RESTRICT_PERMISSIONS
#define SGX_IOC_ENCLAVE_RESTRICT_PERMISSIONS \
    _IOWR(SGX_MAGIC, 0x05, struct sgx_enclave_restrict_permissions)
struct sgx_enclave_restrict_permissions {
    uint64_t offset;
    uint64_t length;
    uint64_t permissions;
    uint64_t result;
    uint64_t count;
};
#endif // SGX_IOC_ENCLAVE_RESTRICT_PERMISSIONS

#ifndef SGX_IOC_ENCLAVE_MODIFY_TYPES
#define SGX_IOC_ENCLAVE_MODIFY_TYPES _IOWR(SGX_MAGIC, 0x06, struct sgx_enclave_modify_types)
struct sgx_enclave_modify_types {
    uint64_t offset;
    uint64_t length;
    uint64_t page_type;
    uint64_t result;
    uint64_t count;
};
#endif // SGX_IOC_ENCLAVE_MODIFY_TYPES

#ifndef SGX_IOC_ENCLAVE_REMOVE_PAGES
#define SGX_IOC_ENCLAVE_REMOVE_PAGES _IOWR(SGX_MAGIC, 0x07, struct sgx_enclave_remove_pages)
struct sgx_enclave_remove_pages {
    uint64_t offset;
    uint64_t length;
    uint64_t count;
};
#endif // SGX_IOC_ENCLAVE_REMOVE_PAGES
