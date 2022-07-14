/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

#include "pal_internal.h"

#define BPI  32
#define POWER2(power) \
    (1ULL << (power))
#define RIGHTMASK(width) \
    (((unsigned long)(width) >= BPI) ? ~0ULL : POWER2(width) - 1ULL)

#define BIT_EXTRACT_LE(value, start, after) \
    (((unsigned long)(value) & RIGHTMASK(after)) >> start)

#define FOUR_CHARS_VALUE(s, w)      \
    (s)[0] = (w) & 0xff;            \
    (s)[1] = ((w) >>  8) & 0xff;    \
    (s)[2] = ((w) >> 16) & 0xff;    \
    (s)[3] = ((w) >> 24) & 0xff;

/*
 *  List of x86 CPU feature flags. This list was last revised in July 2022, see below for details:
 *
 * - https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/Documentation/x86/cpuinfo.rst
 * - https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/arch/x86/include/asm/cpufeatures.h
 *
 * TODO: add AMD-specific flags once needed.
 */

static const char* const g_cpu_flags_cpuid_1_ecx[] = {
    [0]  = "pni",                /* "pni" SSE-3 */
    [1]  = "pclmulqdq",          /* PCLMULQDQ instruction */
    [2]  = "dtes64",             /* 64-bit Debug Store */
    [3]  = "monitor",            /* "monitor" MONITOR/MWAIT support */
    [4]  = "ds_cpl",             /* "ds_cpl" CPL-qualified (filtered) Debug Store */
    [5]  = "vmx",                /* Hardware virtualization */
    [6]  = "smx",                /* Safer Mode eXtensions */
    [7]  = "est",                /* Enhanced SpeedStep */
    [8]  = "tm2",                /* Thermal Monitor 2 */
    [9]  = "ssse3",              /* Supplemental SSE-3 */
    [10] = "cid",                /* Context ID */
    [11] = "sdbg",               /* Silicon Debug */
    [12] = "fma",                /* Fused multiply-add */
    [13] = "cx16",               /* CMPXCHG16B instruction */
    [14] = "xtpr",               /* Send Task Priority Messages */
    [15] = "pdcm",               /* Perf/Debug Capabilities MSR */
    [17] = "pcid",               /* Process Context Identifiers */
    [18] = "dca",                /* Direct Cache Access */
    [19] = "sse4_1",             /* "sse4_1" SSE-4.1 */
    [20] = "sse4_2",             /* "sse4_2" SSE-4.2 */
    [21] = "x2apic",             /* X2APIC */
    [22] = "movbe",              /* MOVBE instruction */
    [23] = "popcnt",             /* POPCNT instruction */
    [24] = "tsc_deadline_timer", /* TSC deadline timer */
    [25] = "aes",                /* AES instructions */
    [26] = "xsave",              /* XSAVE/XRSTOR/XSETBV/XGETBV instructions */
    [27] = "",                   /* "" XSAVE instruction enabled in the OS */
    [28] = "avx",                /* Advanced Vector Extensions */
    [29] = "f16c",               /* 16-bit FP conversions */
    [30] = "rdrand",             /* RDRAND instruction */
    [31] = "hypervisor",         /* Running on a hypervisor */
};

static const char* const g_cpu_flags_cpuid_1_edx[] = {
    [0]  = "fpu",     /* Onboard FPU */
    [1]  = "vme",     /* Virtual Mode Extensions */
    [2]  = "de",      /* Debugging Extensions */
    [3]  = "pse",     /* Page Size Extensions */
    [4]  = "tsc",     /* Time Stamp Counter */
    [5]  = "msr",     /* Model-Specific Registers */
    [6]  = "pae",     /* Physical Address Extensions */
    [7]  = "mce",     /* Machine Check Exception */
    [8]  = "cx8",     /* CMPXCHG8 instruction */
    [9]  = "apic",    /* Onboard APIC */
    [11] = "sep",     /* SYSENTER/SYSEXIT */
    [12] = "mtrr",    /* Memory Type Range Registers */
    [13] = "pge",     /* Page Global Enable */
    [14] = "mca",     /* Machine Check Architecture */
    [15] = "cmov",    /* CMOV instructions (plus FCMOVcc, FCOMI with FPU) */
    [16] = "pat",     /* Page Attribute Table */
    [17] = "pse36",   /* 36-bit PSEs */
    [18] = "pn",      /* Processor serial number */
    [19] = "clflush", /* CLFLUSH instruction */
    [21] = "dts",     /* "dts" Debug Store */
    [22] = "acpi",    /* ACPI via MSR */
    [23] = "mmx",     /* Multimedia Extensions */
    [24] = "fxsr",    /* FXSAVE/FXRSTOR, CR4.OSFXSR */
    [25] = "sse",     /* "sse" */
    [26] = "sse2",    /* "sse2" */
    [27] = "ss",      /* "ss" CPU self snoop */
    [28] = "ht",      /* Hyper-Threading */
    [29] = "tm",      /* "tm" Automatic clock control */
    [30] = "ia64",    /* IA-64 processor */
    [31] = "pbe",     /* Pending Break Enable */
};

static const char* const g_cpu_flags_cpuid_6_eax[] = {
    [0]  = "dtherm",         /* Digital Thermal Sensor */
    [1]  = "ida",            /* Intel Dynamic Acceleration */
    [2]  = "arat",           /* Always Running APIC Timer */
    [4]  = "pln",            /* Intel Power Limit Notification */
    [6]  = "pts",            /* Intel Package Thermal Status */
    [7]  = "hwp",            /* Intel Hardware P-states */
    [8]  = "hwp_notify",     /* HWP Notification */
    [9]  = "hwp_act_window", /* HWP Activity Window */
    [10] = "hwp_epp",        /* HWP Energy Perf. Preference */
    [11] = "hwp_pkg_req",    /* HWP Package Level Request */
    [19] = "hfi",            /* Hardware Feedback Interface */
};

static const char* const g_cpu_flags_cpuid_7_0_ebx[] = {
    [0]  = "fsgsbase",        /* RDFSBASE, WRFSBASE, RDGSBASE, WRGSBASE instructions*/
    [1]  = "tsc_adjust",      /* TSC adjustment MSR 0x3B */
    [2]  = "sgx",             /* Software Guard Extensions */
    [3]  = "bmi1",            /* 1st group bit manipulation extensions */
    [4]  = "hle",             /* Hardware Lock Elision */
    [5]  = "avx2",            /* AVX2 instructions */
    [6]  = "",                /* "" FPU data pointer updated only on x87 exceptions */
    [7]  = "smep",            /* Supervisor Mode Execution Protection */
    [8]  = "bmi2",            /* 2nd group bit manipulation extensions */
    [9]  = "erms",            /* Enhanced REP MOVSB/STOSB instructions */
    [10] = "invpcid",         /* Invalidate Processor Context ID */
    [11] = "rtm",             /* Restricted Transactional Memory */
    [12] = "cqm",             /* Cache QoS Monitoring */
    [13] = "",                /* "" Zero out FPU CS and FPU DS */
    [14] = "mpx",             /* Memory Protection Extension */
    [15] = "rdt_a",           /* Resource Director Technology Allocation */
    [16] = "avx512f",         /* AVX-512 Foundation */
    [17] = "avx512dq",        /* AVX-512 DQ (Double/Quad granular) Instructions */
    [18] = "rdseed",          /* RDSEED instruction */
    [19] = "adx",             /* ADCX and ADOX instructions */
    [20] = "smap",            /* Supervisor Mode Access Prevention */
    [21] = "avx512ifma",      /* AVX-512 Integer Fused Multiply-Add instructions */
    [23] = "clflushopt",      /* CLFLUSHOPT instruction */
    [24] = "clwb",            /* CLWB instruction */
    [25] = "intel_pt",        /* Intel Processor Trace */
    [26] = "avx512pf",        /* AVX-512 Prefetch */
    [27] = "avx512er",        /* AVX-512 Exponential and Reciprocal */
    [28] = "avx512cd",        /* AVX-512 Conflict Detection */
    [29] = "sha_ni",          /* SHA1/SHA256 Instruction Extensions */
    [30] = "avx512bw",        /* AVX-512 BW (Byte/Word granular) Instructions */
    [31] = "avx512vl",        /* AVX-512 VL (128/256 Vector Length) Extensions */
};

static const char* const g_cpu_flags_cpuid_7_0_ecx[] = {
    [1]  = "avx512vbmi",       /* AVX512 Vector Bit Manipulation instructions*/
    [2]  = "umip",             /* User Mode Instruction Protection */
    [3]  = "pku",              /* Protection Keys for Userspace */
    [4]  = "ospke",            /* OS Protection Keys Enable */
    [5]  = "waitpkg",          /* UMONITOR/UMWAIT/TPAUSE Instructions */
    [6]  = "avx512_vbmi2",     /* Additional AVX512 Vector Bit Manipulation Instructions */
    [8]  = "gfni",             /* Galois Field New Instructions */
    [9]  = "vaes",             /* Vector AES */
    [10] = "vpclmulqdq",       /* Carry-Less Multiplication Double Quadword */
    [11] = "avx512_vnni",      /* Vector Neural Network Instructions */
    [12] = "avx512_bitalg",    /* Support for VPOPCNT[B,W] and VPSHUF-BITQMB instructions */
    [13] = "tme",              /* Intel Total Memory Encryption */
    [14] = "avx512_vpopcntdq", /* POPCNT for vectors of DW/QW */
    [16] = "la57",             /* 5-level page tables */
    [22] = "rdpid",            /* RDPID instruction */
    [24] = "bus_lock_detect",  /* Bus Lock detect */
    [25] = "cldemote",         /* CLDEMOTE instruction */
    [27] = "movdiri",          /* MOVDIRI instruction */
    [28] = "movdir64b",        /* MOVDIR64B instruction */
    [29] = "enqcmd",           /* ENQCMD and ENQCMDS instructions */
    [30] = "sgx_lc",           /* Software Guard Extensions Launch Control */
};

static const char* const g_cpu_flags_cpuid_7_0_edx[] = {
    [2]  = "avx512_4vnniw",       /* AVX-512 Neural Network Instructions */
    [3]  = "avx512_4fmaps",       /* AVX-512 Multiply Accumulation Single precision */
    [4]  = "fsrm",                /* Fast Short Rep Mov */
    [8]  = "avx512_vp2intersect", /* AVX-512 Intersect for D/Q */
    [9]  = "",                    /* "" SRBDS mitigation MSR available */
    [10] = "md_clear",            /* VERW clears CPU buffers */
    [11] = "",                    /* "" RTM transaction always aborts */
    [13] = "",                    /* "" TSX_FORCE_ABORT */
    [14] = "serialize",           /* SERIALIZE instruction */
    [15] = "",                    /* "" This part has CPUs of more than one type */
    [16] = "tsxldtrk",            /* TSX Suspend Load Address Tracking */
    [18] = "pconfig",             /* Intel PCONFIG */
    [19] = "arch_lbr",            /* Intel ARCH LBR */
    [20] = "ibt",                 /* Indirect Branch Tracking */
    [22] = "amx_bf16",            /* AMX bf16 Support */
    [23] = "avx512_fp16",         /* AVX512 FP16 */
    [24] = "amx_tile",            /* AMX tile Support */
    [25] = "amx_int8",            /* AMX int8 Support */
    [26] = "",                    /* "" Speculation Control (IBRS + IBPB) */
    [27] = "",                    /* "" Single Thread Indirect Branch Predictors */
    [28] = "flush_l1d",           /* Flush L1D cache */
    [29] = "arch_capabilities",   /* IA32_ARCH_CAPABILITIES MSR (Intel) */
    [30] = "",                    /* "" IA32_CORE_CAPABILITIES MSR */
    [31] = "",                    /* "" Speculative Store Bypass Disable */
};

static const char* const g_cpu_flags_cpuid_7_1_eax[] = {
    [4] = "avx_vnni",    /* AVX VNNI instructions */
    [5] = "avx512_bf16", /* AVX512 BFLOAT16 instructions */
};

static const char* const g_cpu_flags_cpuid_d_1_eax[] = {
    [0] = "xsaveopt", /* XSAVEOPT instruction */
    [1] = "xsavec",   /* XSAVEC instruction */
    [2] = "xgetbv1",  /* XGETBV with ECX = 1 instruction */
    [3] = "xsaves",   /* XSAVES/XRSTORS instructions */
    [4] = "",         /* "" eXtended Feature Disabling */
};

static const char* const g_cpu_flags_cpuid_8000_0001_ecx[] = {
    [0]  = "lahf_lm",       /* LAHF/SAHF in long mode */
    [1]  = "cmp_legacy",    /* If yes HyperThreading not valid */
    [2]  = "svm",           /* Secure Virtual Machine */
    [3]  = "extapic",       /* Extended APIC space */
    [4]  = "cr8_legacy",    /* CR8 in 32-bit mode */
    [5]  = "abm",           /* Advanced bit manipulation */
    [6]  = "sse4a",         /* SSE-4A */
    [7]  = "misalignsse",   /* Misaligned SSE mode */
    [8]  = "3dnowprefetch", /* 3DNow prefetch instructions */
    [9]  = "osvw",          /* OS Visible Workaround */
    [10] = "ibs",           /* Instruction Based Sampling */
    [11] = "xop",           /* extended AVX instructions */
    [12] = "skinit",        /* SKINIT/STGI instructions */
    [13] = "wdt",           /* Watchdog timer */
    [15] = "lwp",           /* Light Weight Profiling */
    [16] = "fma4",          /* 4 operands MAC instructions */
    [17] = "tce",           /* Translation Cache Extension */
    [19] = "nodeid_msr",    /* NodeId MSR */
    [21] = "tbm",           /* Trailing Bit Manipulations */
    [22] = "topoext",       /* Topology extensions CPUID leafs */
    [23] = "perfctr_core",  /* Core performance counter extensions */
    [24] = "perfctr_nb",    /* NB performance counter extensions */
    [26] = "bpext",         /* Data breakpoint extension */
    [27] = "ptsc",          /* Performance time-stamp counter */
    [28] = "perfctr_llc",   /* Last Level Cache performance counter extensions */
    [29] = "mwaitx",        /* MWAIT extension (MONITORX/MWAITX instructions) */
};

static const char* const g_cpu_flags_cpuid_8000_0001_edx[] = {
    [11] = "syscall",  /* SYSCALL/SYSRET */
    [19] = "mp",       /* MP Capable */
    [20] = "nx",       /* Execute Disable */
    [22] = "mmxext",   /* AMD MMX extensions */
    [25] = "fxsr_opt", /* FXSAVE/FXRSTOR optimizations */
    [26] = "pdpe1gb",  /* "pdpe1gb" GB pages */
    [27] = "rdtscp",   /* RDTSCP */
    [29] = "lm",       /* Long Mode (x86-64, 64-bit support) */
    [30] = "3dnowext", /* AMD 3DNow extensions */
    [31] = "3dnow",    /* 3DNow */
};

static int extend_cap_flags(const char* const cpu_flags[], const unsigned int* words,
                            enum CPUID_WORD w, char** flags, size_t* flen, size_t* fmax) {
    assert(*flags != NULL);

    for (int i = 0; i < 32; i++) {
        if (!cpu_flags[i] || strlen(cpu_flags[i]) == 0)
            continue;

        if (BIT_EXTRACT_LE(words[w], i, i + 1)) {
            size_t len = strlen(cpu_flags[i]);
            if (*flen + len + 1 > *fmax) {
                char* new_flags = malloc(*fmax * 2);
                if (!new_flags) {
                    return -PAL_ERROR_NOMEM;
                }
                memcpy(new_flags, *flags, *flen);
                free(*flags);
                *fmax *= 2;
                *flags = new_flags;
            }
            memcpy(*flags + *flen, cpu_flags[i], len);
            *flen += len;
            (*flags)[(*flen)++] = ' ';
        }
    }

    return 0;
}

#define EXTEND_CAP_FLAGS(cpu_flags, reg)                                           \
    rv = extend_cap_flags(cpu_flags, words, reg, &flags, &flen, &fmax);            \
    if (rv < 0) {                                                                  \
        goto out_err;                                                              \
    }                                                                              \

int _PalGetCPUInfo(struct pal_cpu_info* ci) {
    unsigned int words[CPUID_WORD_NUM];
    int rv = 0;
    char* flags = NULL;
    char* brand = NULL;
    char* vendor_id = NULL;

    const size_t VENDOR_ID_SIZE = 13;
    vendor_id = malloc(VENDOR_ID_SIZE);
    if (!vendor_id)
        return -PAL_ERROR_NOMEM;

    _PalCpuIdRetrieve(0, 0, words);
    unsigned int cpuid_level = words[CPUID_WORD_EAX];
    FOUR_CHARS_VALUE(&vendor_id[0], words[CPUID_WORD_EBX]);
    FOUR_CHARS_VALUE(&vendor_id[4], words[CPUID_WORD_EDX]);
    FOUR_CHARS_VALUE(&vendor_id[8], words[CPUID_WORD_ECX]);
    vendor_id[VENDOR_ID_SIZE - 1] = '\0';
    ci->cpu_vendor = vendor_id;

    const size_t BRAND_SIZE = 49;
    brand = malloc(BRAND_SIZE);
    if (!brand) {
        rv = -PAL_ERROR_NOMEM;
        goto out_err;
    }

    _PalCpuIdRetrieve(0x80000000, 0, words);
    unsigned int extended_cpuid_level = words[CPUID_WORD_EAX];
    if (extended_cpuid_level < 0x80000004) {
        goto out_err;
    }

    _PalCpuIdRetrieve(0x80000002, 0, words);
    memcpy(&brand[ 0], words, sizeof(unsigned int) * CPUID_WORD_NUM);
    _PalCpuIdRetrieve(0x80000003, 0, words);
    memcpy(&brand[16], words, sizeof(unsigned int) * CPUID_WORD_NUM);
    _PalCpuIdRetrieve(0x80000004, 0, words);
    memcpy(&brand[32], words, sizeof(unsigned int) * CPUID_WORD_NUM);
    brand[BRAND_SIZE - 1] = '\0';
    ci->cpu_brand = brand;

    _PalCpuIdRetrieve(1, 0, words);
    ci->cpu_family   = BIT_EXTRACT_LE(words[CPUID_WORD_EAX], 8, 12);
    ci->cpu_model    = BIT_EXTRACT_LE(words[CPUID_WORD_EAX], 4, 8);
    ci->cpu_stepping = BIT_EXTRACT_LE(words[CPUID_WORD_EAX], 0, 4);

    if (!memcmp(vendor_id, "GenuineIntel", 12) || !memcmp(vendor_id, "AuthenticAMD", 12)) {
        ci->cpu_family += BIT_EXTRACT_LE(words[CPUID_WORD_EAX], 20, 28);
        ci->cpu_model  += BIT_EXTRACT_LE(words[CPUID_WORD_EAX], 16, 20) << 4;
    }

    size_t flen = 0;
    size_t fmax = 80;
    flags = malloc(fmax);
    if (!flags) {
        rv = -PAL_ERROR_NOMEM;
        goto out_err;
    }

    /* Intel-defined flags: level 0x00000001 */
    EXTEND_CAP_FLAGS(g_cpu_flags_cpuid_1_ecx, CPUID_WORD_ECX);
    EXTEND_CAP_FLAGS(g_cpu_flags_cpuid_1_edx, CPUID_WORD_EDX);

    /* Thermal and Power Management Leaf: level 0x00000006 (eax) */
    if (cpuid_level >= 0x00000006) {
        _PalCpuIdRetrieve(0x00000006, 0, words);

        EXTEND_CAP_FLAGS(g_cpu_flags_cpuid_6_eax, CPUID_WORD_EAX);
    }

    /* Additional Intel-defined flags: level 0x00000007 */
    if (cpuid_level >= 0x00000007) {
        _PalCpuIdRetrieve(0x00000007, 0, words);

        unsigned int eax = words[CPUID_WORD_EAX];
        EXTEND_CAP_FLAGS(g_cpu_flags_cpuid_7_0_ebx, CPUID_WORD_EBX);
        EXTEND_CAP_FLAGS(g_cpu_flags_cpuid_7_0_ecx, CPUID_WORD_ECX);
        EXTEND_CAP_FLAGS(g_cpu_flags_cpuid_7_0_edx, CPUID_WORD_EDX);

        /* Check valid sub-leaf index before accessing it */
        if (eax >= 1) {
            _PalCpuIdRetrieve(0x00000007, 1, words);

            EXTEND_CAP_FLAGS(g_cpu_flags_cpuid_7_1_eax, CPUID_WORD_EAX);
        }
    }

    /* Extended state features: level 0x0000000d */
    if (cpuid_level >= 0x0000000d) {
        _PalCpuIdRetrieve(0x0000000d, 1, words);

        EXTEND_CAP_FLAGS(g_cpu_flags_cpuid_d_1_eax, CPUID_WORD_EAX);
    }

    /* AMD-defined flags: level 0x80000001 */
    _PalCpuIdRetrieve(0x80000001, 0, words);

    EXTEND_CAP_FLAGS(g_cpu_flags_cpuid_8000_0001_ecx, CPUID_WORD_ECX);
    EXTEND_CAP_FLAGS(g_cpu_flags_cpuid_8000_0001_edx, CPUID_WORD_EDX);

    /* End the capability flags extension */
    flags[flen ? flen - 1 : 0] = 0;

    ci->cpu_flags = flags;

    ci->cpu_bogomips = _PalGetBogomips();
    if (ci->cpu_bogomips == 0.0) {
        log_warning("bogomips could not be retrieved, passing 0.0 to the application");
    }

    return 0;

out_err:
    free(flags);
    free(brand);
    free(vendor_id);
    return rv;
}
