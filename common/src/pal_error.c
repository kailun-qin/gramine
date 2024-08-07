/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#include "api.h"
#include "pal_error.h"

#define IDX(x) [-(x)]
static const char* g_pal_error_list[] = {
    IDX(PAL_ERROR_SUCCESS) = "Success (PAL_ERROR_SUCCESS)",
    IDX(PAL_ERROR_NOTIMPLEMENTED) = "Function not implemented (PAL_ERROR_NOTIMPLEMENTED)",
    IDX(PAL_ERROR_NOTDEFINED) = "Symbol not defined (PAL_ERROR_NOTDEFINED)",
    IDX(PAL_ERROR_NOTSUPPORT) = "Function not supported (PAL_ERROR_NOTSUPPORT)",
    IDX(PAL_ERROR_INVAL) = "Invalid argument (PAL_ERROR_INVAL)",
    IDX(PAL_ERROR_TOOLONG) = "Name/path is too long (PAL_ERROR_TOOLONG)",
    IDX(PAL_ERROR_DENIED) = "Operation denied (PAL_ERROR_DENIED)",
    IDX(PAL_ERROR_BADHANDLE) = "Handle corrupted (PAL_ERROR_BADHANDLE)",
    IDX(PAL_ERROR_STREAMEXIST) = "Stream already exists (PAL_ERROR_STREAMEXIST)",
    IDX(PAL_ERROR_STREAMNOTEXIST) = "Stream does not exist (PAL_ERROR_STREAMNOTEXIST)",
    IDX(PAL_ERROR_STREAMISFILE) = "Stream is a file (PAL_ERROR_STREAMISFILE)",
    IDX(PAL_ERROR_STREAMISDIR) = "Stream is a directory (PAL_ERROR_STREAMISDIR)",
    IDX(PAL_ERROR_STREAMISDEVICE) = "Stream is a device (PAL_ERROR_STREAMISDEVICE)",
    IDX(PAL_ERROR_INTERRUPTED) = "Operation interrupted (PAL_ERROR_INTERRUPTED)",
    IDX(PAL_ERROR_OVERFLOW) = "Buffer overflowed (PAL_ERROR_OVERFLOW)",
    IDX(PAL_ERROR_BADADDR) = "Invalid address (PAL_ERROR_BADADDR)",
    IDX(PAL_ERROR_NOMEM) = "Not enough memory (PAL_ERROR_NOMEM)",
    IDX(PAL_ERROR_INCONSIST) = "Inconsistent system state (PAL_ERROR_INCONSIST)",
    IDX(PAL_ERROR_TRYAGAIN) = "Try again (PAL_ERROR_TRYAGAIN)",
    IDX(PAL_ERROR_NOTSERVER) = "Not a server (PAL_ERROR_NOTSERVER)",
    IDX(PAL_ERROR_NOTCONNECTION) = "Not a connection (PAL_ERROR_NOTCONNECTION)",
    IDX(PAL_ERROR_CONNFAILED) = "Connection failed (PAL_ERROR_CONNFAILED)",
    IDX(PAL_ERROR_ADDRNOTEXIST) = "Resource address does not exist (PAL_ERROR_ADDRNOTEXIST)",
    IDX(PAL_ERROR_AFNOSUPPORT) = "Address family not supported by protocol (PAL_ERROR_AFNOSUPPORT)",
    IDX(PAL_ERROR_CONNFAILED_PIPE) = "Broken pipe (PAL_ERROR_CONNFAILED_PIPE)",

    IDX(PAL_ERROR_CRYPTO_FEATURE_UNAVAILABLE) = "[Crypto] Feature not available (PAL_ERROR_CRYPTO_FEATURE_UNAVAILABLE)",
    IDX(PAL_ERROR_CRYPTO_INVALID_CONTEXT) = "[Crypto] Invalid context (PAL_ERROR_CRYPTO_INVALID_CONTEXT)",
    IDX(PAL_ERROR_CRYPTO_INVALID_KEY_LENGTH) = "[Crypto] Invalid key length (PAL_ERROR_CRYPTO_INVALID_KEY_LENGTH)",
    IDX(PAL_ERROR_CRYPTO_INVALID_INPUT_LENGTH) = "[Crypto] Invalid input length (PAL_ERROR_CRYPTO_INVALID_INPUT_LENGTH)",
    IDX(PAL_ERROR_CRYPTO_INVALID_OUTPUT_LENGTH) = "[Crypto] Invalid output length (PAL_ERROR_CRYPTO_INVALID_OUTPUT_LENGTH)",
    IDX(PAL_ERROR_CRYPTO_BAD_INPUT_DATA) = "[Crypto] Bad input parameters (PAL_ERROR_CRYPTO_BAD_INPUT_DATA)",
    IDX(PAL_ERROR_CRYPTO_INVALID_PADDING) = "[Crypto] Invalid padding (PAL_ERROR_CRYPTO_INVALID_PADDING)",
    IDX(PAL_ERROR_CRYPTO_DATA_MISALIGNED) = "[Crypto] Data misaligned (PAL_ERROR_CRYPTO_DATA_MISALIGNED)",
    IDX(PAL_ERROR_CRYPTO_INVALID_FORMAT) = "[Crypto] Invalid data format (PAL_ERROR_CRYPTO_INVALID_FORMAT)",
    IDX(PAL_ERROR_CRYPTO_AUTH_FAILED) = "[Crypto] Authentication failed (PAL_ERROR_CRYPTO_AUTH_FAILED)",
    IDX(PAL_ERROR_CRYPTO_IO_ERROR) = "[Crypto] I/O error (PAL_ERROR_CRYPTO_IO_ERROR)",
    IDX(PAL_ERROR_CRYPTO_KEY_GEN_FAILED) = "[Crypto] Key generation failed (PAL_ERROR_CRYPTO_KEY_GEN_FAILED)",
    IDX(PAL_ERROR_CRYPTO_INVALID_KEY) = "[Crypto] Invalid key (PAL_ERROR_CRYPTO_INVALID_KEY)",
    IDX(PAL_ERROR_CRYPTO_VERIFY_FAILED) = "[Crypto] Verification failed (PAL_ERROR_CRYPTO_VERIFY_FAILED)",
    IDX(PAL_ERROR_CRYPTO_RNG_FAILED) = "[Crypto] RNG failed to generate data (PAL_ERROR_CRYPTO_RNG_FAILED)",
    IDX(PAL_ERROR_CRYPTO_INVALID_DH_STATE) = "[Crypto] Invalid DH state (PAL_ERROR_CRYPTO_INVALID_DH_STATE)",
};
#undef IDX

const char* pal_strerror(int err) {
    unsigned err_idx = err >= 0 ? err : -err;
    if (err_idx >= ARRAY_SIZE(g_pal_error_list) || !g_pal_error_list[err_idx]) {
        log_error("Unknown PAL error (errcode = %d)", err);
        abort();
    }
    return g_pal_error_list[err_idx];
}
