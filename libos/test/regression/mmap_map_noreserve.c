/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation
 *                    Kailun Qin <kailun.qin@intel.com>
 */

/*
 * Test for creating and accessing anonymous mappings with `MAP_NORESERVE`.
 *
 * This test works on both EDMM and non-EDMM platforms, but if EDMM (and EXINFO) is enabled, the
 * enclave pages are not actually committed on mmap requests, but instead they are lazily committed
 * on first access. This test stresses the lazy-allocation logic on fork (again, only the
 * actually-accessed enclave pages will be copied to the child enclave). This test also stresses
 * races between several threads on the same lazily-allocated page.
 *
 * Therefore, on EDMM-enabled platforms, the test is supposed to be significantly faster than on
 * non-EDMM-enabled platforms. But functionality-wise it will be the same. For example, on an ICX
 * machine, this test takes ~0.9s with EDMM enabled and ~12.6s with EDMM disabled.
 */

#define _GNU_SOURCE
#include <err.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

#include "common.h"

#define NUM_THREADS 5
#define PAGE_SIZE (1ul << 12)
#define TEST_FILE "testfile_map_noreserve"
#define TEST_LENGTH  0xC0000000
#define TEST_LENGTH2  0xC000000
#define TEST_LENGTH3     0xA000
#define TEST_RACE_NUM_ITERATIONS 100

static int g_urandom_fd;

static bool g_write_failed;
static bool g_read_failed;

void mem_write(void* addr, uint8_t val) __attribute__((visibility("internal")));
uint8_t mem_read(void* addr) __attribute__((visibility("internal")));
static bool is_pc_at_func(uintptr_t pc, void (*func)(void));
static void fixup_context_after_write(ucontext_t* context);
static void fixup_context_after_read(ucontext_t* context);

#ifdef __x86_64__
void ret(void) __attribute__((visibility("internal")));
void end_of_ret(void) __attribute__((visibility("internal")));
__asm__ (
".pushsection .text\n"
".type mem_write, @function\n"
".type mem_read, @function\n"
".type ret, @function\n"
".type end_of_ret, @function\n"
"mem_write:\n"
    "movb %sil, (%rdi)\n"
    "ret\n"
"mem_read:\n"
    "movb (%rdi), %al\n"
    "ret\n"
"ret:\n"
    "ret\n"
"end_of_ret:\n"
".popsection\n"
);

static bool is_pc_at_func(uintptr_t pc, void (*func)(void)) {
    return pc == (uintptr_t)func;
}

static void fixup_context_after_write(ucontext_t* context) {
    context->uc_mcontext.gregs[REG_RIP] = (greg_t)ret;
}

static void fixup_context_after_read(ucontext_t* context) {
    context->uc_mcontext.gregs[REG_RIP] = (greg_t)ret;
    context->uc_mcontext.gregs[REG_RAX] = 0;
}

#else
#error Unsupported architecture
#endif

static void memfault_handler(int signum, siginfo_t* info, void* context) {
    ucontext_t* uc = (ucontext_t*)context;
    uintptr_t pc = uc->uc_mcontext.gregs[REG_RIP];

    if (is_pc_at_func(pc, (void (*)(void))mem_write)) {
        fixup_context_after_write(uc);
        g_write_failed = true;
        return;
    } else if (is_pc_at_func(pc, (void (*)(void))mem_read)) {
        fixup_context_after_read(uc);
        g_read_failed = true;
        return;
    }

    errx(1, "unexpected memory fault at: %#lx (pc: %#lx)\n", (uintptr_t)info->si_addr, pc);
}

static unsigned long get_random_ulong(void) {
    unsigned long random_num;
    ssize_t x = CHECK(read(g_urandom_fd, &random_num, sizeof(random_num)));
    if (x != sizeof(random_num))
        errx(1, "/dev/urandom read: %zd", x);

    return random_num;
}

/* To stress races between several threads on the same lazily-allocated page, we repeatedly touch
 * different pages at random and mix with `madvise(MADV_DONTNEED)` called (with not too many pages,
 * so that it has a reasonable chance of collision). */
static void* thread_func(void* arg) {
    int ret;
    char data;
    size_t num_pages = TEST_LENGTH3 / PAGE_SIZE;

    for (int i = 0; i < TEST_RACE_NUM_ITERATIONS; i++) {
        size_t page = get_random_ulong() % num_pages;
        data = READ_ONCE(((char*)arg)[page * PAGE_SIZE]);
        if (data != 0)
            return (void*)1;

        page = get_random_ulong() % num_pages;
        ret = madvise(arg + page * PAGE_SIZE, PAGE_SIZE, MADV_DONTNEED);
        if (ret)
            return (void*)1;
    }
    return (void*)0;
}

int main(void) {
    setbuf(stdout, NULL);
    g_urandom_fd = CHECK(open("/dev/urandom", O_RDONLY));

    struct sigaction action = {
        .sa_sigaction = memfault_handler,
        .sa_flags = SA_SIGINFO,
    };
    CHECK(sigaction(SIGSEGV, &action, NULL));

    /* test anonymous mappings with `MAP_NORESERVE` */
    char* a = mmap(NULL, TEST_LENGTH, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1,
                   0);
    if (a == MAP_FAILED)
        err(1, "mmap 1");

    size_t offset = get_random_ulong() % TEST_LENGTH;
    char data = READ_ONCE(a[offset]);
    if (data != 0)
        errx(1, "unexpected value read (expected: %x, actual: %x)", 0, data);

    const char expected_val = 0xff;
    offset = get_random_ulong() % TEST_LENGTH;

    g_write_failed = false;
    COMPILER_BARRIER();
    mem_write(&a[offset], expected_val);
    COMPILER_BARRIER();
    if (g_write_failed)
        puts("write to R mem got SIGSEGV");

    CHECK(mprotect(a, TEST_LENGTH, PROT_READ | PROT_WRITE));

    offset = get_random_ulong() % TEST_LENGTH;
    WRITE_ONCE(a[offset], expected_val);

    CHECK(madvise(a, TEST_LENGTH, MADV_DONTNEED));
    data = READ_ONCE(a[offset]);
    if (data != 0)
        errx(1, "unexpected value read (on 'MAP_NORESERVE') after 'madvise(MADV_DONTNEED)' "
                "(expected: %x, actual: %x)", 0, data);

    CHECK(munmap(a, TEST_LENGTH));

    /* test anonymous mappings without `MAP_NORESERVE` accessed after `madvise(MADV_DONTNEED)` */
    a = mmap(NULL, TEST_LENGTH2, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    offset = get_random_ulong() % TEST_LENGTH2;
    WRITE_ONCE(a[offset], expected_val);

    CHECK(madvise(a, TEST_LENGTH2, MADV_DONTNEED));
    data = READ_ONCE(a[offset]);
    if (data != 0)
        errx(1, "unexpected value read (on non-'MAP_NORESERVE') after 'madvise(MADV_DONTNEED)' "
                "(expected: %x, actual: %x)", 0, data);

    CHECK(munmap(a, TEST_LENGTH2));

    /* test threads racing to access the same page in anonymous mappings with `MAP_NORESERVE` */
    a = mmap(NULL, TEST_LENGTH3, PROT_READ | PROT_WRITE,
             MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
    if (a == MAP_FAILED)
        err(1, "mmap 2");

    pthread_t threads[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_create(&threads[i], NULL, thread_func, a))
            errx(1, "pthread_create failed");
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        void* ret;
        if (pthread_join(threads[i], &ret))
            errx(1, "pthread_join failed");
        if (ret)
            errx(1, "threads returned error");
    }

    CHECK(munmap(a, TEST_LENGTH3));

    /* test anonymous mappings with `MAP_NORESERVE` accessed via file read/write
     *
     * note: we test this because the `read(fd, <mmapped buffer>)` reads into a buffer that was
     * allocated with `MAP_NORESERVE` and thus will commit the enclave pages on demand, while
     * executing the code in the PAL layer (this code writes the host-provided bytes from the file
     * into the mmapped buffer) */
    a = mmap(NULL, TEST_LENGTH2, PROT_READ | PROT_WRITE,
             MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
    if (a == MAP_FAILED)
        err(1, "mmap 3");

    int fd = CHECK(open(TEST_FILE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));

    ssize_t n = CHECK(write(fd, &expected_val, sizeof(expected_val)));
    if (n != sizeof(expected_val))
        err(1, "write");

    CHECK(lseek(fd, 0, SEEK_SET));

    offset = get_random_ulong() % TEST_LENGTH2;
    n = CHECK(read(fd, &a[offset], sizeof(expected_val)));
    if (n != sizeof(expected_val))
        err(1, "read");
    data = READ_ONCE(a[offset]);
    if (data != expected_val)
        errx(1, "unexpected value read from file (expected: %x, actual: %x)", expected_val, data);

    CHECK(munmap(a, TEST_LENGTH2));
    CHECK(close(fd));

    /* test anonymous mappings with `MAP_NORESERVE` on fork */
    a = mmap(NULL, TEST_LENGTH2, PROT_READ | PROT_WRITE,
             MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
    if (a == MAP_FAILED)
        err(1, "mmap 4");

    offset = get_random_ulong() % TEST_LENGTH2;
    WRITE_ONCE(a[offset], expected_val);
    pid_t pid = CHECK(fork());
    if (pid == 0) {
        data = READ_ONCE(a[offset]);
        if (data != expected_val)
            errx(1, "child: unexpected value read (expected: %x, actual: %x)", expected_val, data);
        exit(0);
    }

    int status;
    CHECK(wait(&status));
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        errx(1, "child wait status: %#x", status);

    CHECK(munmap(a, TEST_LENGTH2));

    CHECK(close(g_urandom_fd));
    puts("TEST OK");
    return 0;
}
