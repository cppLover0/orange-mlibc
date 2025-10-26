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

extern "C" void __dlapi_enter(uintptr_t *);

extern char **environ;

extern "C" void __mlibc_entry(uintptr_t *entry_stack, int (*main_fn)(int argc, char *argv[], char *env[])) {
	__dlapi_enter(entry_stack);

	auto result = main_fn(mlibc::entry_stack.argc, mlibc::entry_stack.argv, environ);
	exit(result);
}

extern "C" void __mlibc_start_thread(void *entry, void *user_arg, Tcb *tcb) {
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
