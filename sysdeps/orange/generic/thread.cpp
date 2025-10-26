
#include <stdint.h>
#include <stdlib.h>
#include <bits/ensure.h>
#include <mlibc/elf/startup.h>
#include <mlibc/debug.hpp>

#include <errno.h>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/tcb.hpp>
#include <stddef.h>
#include <sys/mman.h>


extern "C" void __mlibc_enter_thread(void *entry, void *user_arg, Tcb *tcb) {
	// Wait until our parent sets up the TID.
	while (!__atomic_load_n(&tcb->tid, __ATOMIC_RELAXED))
		mlibc::sys_futex_wait(&tcb->tid, 0, nullptr);

	if (mlibc::sys_tcb_set(tcb))
		__ensure(!"sys_tcb_set() failed");

	tcb->invokeThreadFunc(entry, user_arg);

	auto self = reinterpret_cast<Tcb *>(tcb);

	__atomic_store_n(&self->didExit, 1, __ATOMIC_RELEASE);
	mlibc::sys_futex_wake(&self->didExit);

	mlibc::sys_thread_exit();
}

namespace mlibc {

static constexpr size_t default_stacksize = 0x200000;

int sys_prepare_stack(
    void **stack,
    void *entry,
    void *user_arg,
    void *tcb,
    size_t *stack_size,
    size_t *guard_size,
    void **stack_base
) {
	if (!*stack_size)
		*stack_size = default_stacksize;
	*guard_size = 0;

	if (*stack) {
		*stack_base = *stack;
	} else {
		*stack_base =
		    mmap(nullptr, *stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (*stack_base == MAP_FAILED) {
			return errno;
		}
	}

	uintptr_t *sp =
	    reinterpret_cast<uintptr_t *>(reinterpret_cast<uintptr_t>(*stack_base) + *stack_size);

	*--sp = reinterpret_cast<uintptr_t>(tcb);
	*--sp = reinterpret_cast<uintptr_t>(user_arg);
	*--sp = reinterpret_cast<uintptr_t>(entry);
	*stack = reinterpret_cast<void *>(sp);
	return 0;
}

extern "C" void __mlibc_start_thread();

int sys_clone(void *tcb, pid_t *pid_out, void *stack) { 
    int pid;
    int ret;
    uint64_t entry = (uint64_t)__mlibc_thread_entry;
    asm volatile("syscall" : "=a"(ret), "=D"(pid) : "a"(54), "D"(stack) , "S"(entry), "d"(0) : "rcx","r11");
    *pid_out = pid;
    return ret;
}

} // namespace mlibc
