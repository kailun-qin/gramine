#include "api.h"
#include "pal.h"
#include "pal_regression.h"
#include "sgx_arch.h"

#define ALLOC_ALIGN_UP(addr) ALIGN_UP_POW2(addr, PalGetPalPublicState()->alloc_align)

char zerobuf[sizeof(sgx_report_t)] = {0};

int main(int argc, char** argv, char** envp) {
    /* We don't care about unused args to main, but UBSan complains otherwise
     * with "call through pointer with incorrect function type" */
    __UNUSED(envp);

    int ret;

    size_t user_report_data_size;
    size_t target_info_size;
    size_t report_size;
    ret = PalAttestationReport(/*user_report_data=*/NULL, &user_report_data_size,
                               /*target_info=*/NULL, &target_info_size,
                               /*report=*/NULL, &report_size);
    if (ret < 0) {
        pal_printf("ERROR: PalAttestationReport() to get sizes of SGX structs failed\n");
        return -1;
    }

    if (user_report_data_size != sizeof(sgx_report_data_t)) {
        pal_printf("ERROR: PalAttestationReport() returned incorrect user_report_data size\n");
        return -1;
    }

    if (target_info_size != sizeof(sgx_target_info_t)) {
        pal_printf("ERROR: PalAttestationReport() returned incorrect target_info size\n");
        return -1;
    }

    if (report_size != sizeof(sgx_report_t)) {
        pal_printf("ERROR: PalAttestationReport() returned incorrect report size\n");
        return -1;
    }

    pal_printf("user_report_data_size = %lu, target_info_size = %lu, report_size = %lu\n",
               user_report_data_size, target_info_size, report_size);

    void* user_report_data = NULL;
    ret = memory_alloc(ALLOC_ALIGN_UP(user_report_data_size), PAL_PROT_READ | PAL_PROT_WRITE,
                       &user_report_data);
    if (ret < 0) {
        pal_printf("ERROR: Cannot allocate memory for user_report_data\n");
        return -1;
    }

    void* target_info = NULL;
    ret = memory_alloc(ALLOC_ALIGN_UP(target_info_size), PAL_PROT_READ | PAL_PROT_WRITE,
                       &target_info);
    if (ret < 0) {
        pal_printf("ERROR: Cannot allocate memory for target_info\n");
        return -1;
    }

    void* report = NULL;
    ret = memory_alloc(ALLOC_ALIGN_UP(report_size), PAL_PROT_READ | PAL_PROT_WRITE, &report);
    if (ret < 0) {
        pal_printf("ERROR: Cannot allocate memory for report\n");
        return -1;
    }

    memset(user_report_data, 'A', user_report_data_size);
    memset(target_info, 0, target_info_size);
    memset(report, 0, report_size);

    ret = PalAttestationReport(user_report_data, &user_report_data_size, target_info,
                               &target_info_size, report, &report_size);
    if (ret < 0) {
        pal_printf("ERROR: PalAttestationReport() to get SGX report failed\n");
        return -1;
    }

    sgx_report_t* sgx_report = (sgx_report_t*)report;
    if (memcmp(&sgx_report->body.report_data.d, user_report_data,
               sizeof(sgx_report->body.report_data.d))) {
        pal_printf("ERROR: PalAttestationReport() returned SGX report with wrong report_data\n");
        return -1;
    }

    if (memcmp(&sgx_report->body.reserved1, &zerobuf, sizeof(sgx_report->body.reserved1)) ||
        memcmp(&sgx_report->body.reserved2, &zerobuf, sizeof(sgx_report->body.reserved2)) ||
        memcmp(&sgx_report->body.reserved3, &zerobuf, sizeof(sgx_report->body.reserved3)) ||
        memcmp(&sgx_report->body.reserved4, &zerobuf, sizeof(sgx_report->body.reserved4)))
    {
        pal_printf("ERROR: PalAttestationReport() returned SGX report with non-zero reserved "
                   "fields\n");
        return -1;
    }

    if (memory_free(user_report_data, ALLOC_ALIGN_UP(user_report_data_size)) < 0) {
        pal_printf("memory_free on `user_report_data` failed\n");
        return 1;
    }
    if (memory_free(target_info, ALLOC_ALIGN_UP(target_info_size)) < 0) {
        pal_printf("memory_free on `target_info` failed\n");
        return 1;
    }
    if (memory_free(report, ALLOC_ALIGN_UP(report_size)) < 0) {
        pal_printf("memory_free on `report` failed\n");
        return 1;
    }

    pal_printf("Success\n");
    return 0;
}
