/* TODO: Hans, get ze flammenwerfer */

#include <inttypes.h>
#include <stdatomic.h>
#include <stdbool.h>

#include "pal.h"
#include "pal_regression.h"

static void* get_stack(void) {
    void* stack;
    __asm__ volatile("mov %%rsp, %0" : "=r"(stack) :: "memory");
    return stack;
}

static void handler1(bool is_in_pal, uintptr_t addr, PAL_CONTEXT* context) {
    __UNUSED(is_in_pal);

    pal_printf("Arithmetic Exception Handler 1: 0x%08lx, rip = 0x%08lx\n", addr, context->rip);

    pal_printf("Stack in handler: %p\n", get_stack());

    while (*(unsigned char*)context->rip != 0x90)
        context->rip++;
}

static void handler2(bool is_in_pal, uintptr_t addr, PAL_CONTEXT* context) {
    __UNUSED(is_in_pal);

    pal_printf("Arithmetic Exception Handler 2: 0x%08lx, rip = 0x%08lx\n", addr, context->rip);

    while (*(unsigned char*)context->rip != 0x90)
        context->rip++;
}

atomic_bool handler3_called = false;

static void handler3(bool is_in_pal, uintptr_t addr, PAL_CONTEXT* context) {
    __UNUSED(is_in_pal);

    pal_printf("Arithmetic Exception Handler 3: 0x%" PRIx64 ", rip = 0x%" PRIx64 "\n", addr,
               context->rip);

    while (*(unsigned char*)context->rip != 0x90)
        context->rip++;

    handler3_called = true;
}

static void red_zone_test(void) {
    uint64_t res = 0;

    // First call some function to ensure that gcc doesn't use the red zone
    // itself.
    pal_printf("Testing red zone...\n");

    __asm__ volatile(
        // Fill the red zone with a pattern (0xaa 0xa9 0xa8 ...)
        "movq $-128, %%rax\n"
        "movq $0xaa, %%rbx\n"
        "1:\n"
        "movb %%bl, (%%rsp, %%rax, 1)\n"
        "decq %%rbx\n"
        "incq %%rax\n"
        "jnz 1b\n"

        // Trigger exception
        "movq $1, %%rax\n"
        "cqo\n"
        "movq $0, %%rbx\n"
        "divq %%rbx\n"
        "nop\n"

        // Calculate sum of pattern
        "movq $-128, %%rax\n"
        "movq $0, %%rbx\n"
        "movq $0, %%rcx\n"
        "1:\n"
        "movb (%%rsp, %%rax, 1), %%bl\n"
        "addq %%rbx, %%rcx\n"
        "incq %%rax\n"
        "jnz 1b\n"
        "movq %%rcx, %q0\n"
        : "=rm"(res)
        :
        : "rax", "rbx", "rcx", "rdx", "cc", "memory");

    if (!handler3_called) {
        pal_printf("Exception handler was not called!\n");
        return;
    }

    if (res != 13632) {
        pal_printf("Sum over red zone (%lu) doesn't match!\n", res);
        return;
    }

    pal_printf("Red zone test ok.\n");
}

#define INVALID_ADDR 0x1000

static void handler4(bool is_in_pal, uintptr_t addr, PAL_CONTEXT* context) {
    __UNUSED(is_in_pal);

    pal_printf("Memory Fault Exception Handler: 0x%08lx, rip = 0x%08lx\n", addr, context->rip);

    if (addr != INVALID_ADDR)
        pal_printf("Wrong faulting address: expected: 0x%08x, got: 0x%08lx\n", INVALID_ADDR, addr);

    while (*(unsigned char*)context->rip != 0x90)
        context->rip++;
}

int main(int argc, char** argv, char** envp) {
    /* We don't care about unused args to main, but UBSan complains otherwise
     * with "call through pointer with incorrect function type" */
    __UNUSED(argc);
    __UNUSED(argv);
    __UNUSED(envp);

    pal_printf("Stack in main: %p\n", get_stack());

    PalSetExceptionHandler(handler1, PAL_EVENT_ARITHMETIC_ERROR);
    __asm__ volatile (
            "movq $1, %%rax\n"
            "cqo\n"
            "movq $0, %%rbx\n"
            "divq %%rbx\n"
            "nop\n"
            ::: "rax", "rbx", "rdx", "cc");

    PalSetExceptionHandler(handler2, PAL_EVENT_ARITHMETIC_ERROR);
    __asm__ volatile (
            "movq $1, %%rax\n"
            "cqo\n"
            "movq $0, %%rbx\n"
            "divq %%rbx\n"
            "nop\n"
            ::: "rax", "rbx", "rdx", "cc");

    PalSetExceptionHandler(handler3, PAL_EVENT_ARITHMETIC_ERROR);
    red_zone_test();

    /* For Gramine-SGX, memory fault exception handling test will error out and fail on machines
     * that do not support EXINFO. We thus put it as the last test so that we could still check on
     * the other tests in such case. */
    PalSetExceptionHandler(handler4, PAL_EVENT_MEMFAULT);
    *(volatile long*)INVALID_ADDR = 0;
    __asm__ volatile("nop");

    return 0;
}
