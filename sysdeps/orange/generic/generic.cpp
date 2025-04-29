#include <mlibc/all-sysdeps.hpp>
#include <mlibc/debug.hpp>

namespace mlibc {

void sys_exit(int status) {
   asm volatile("syscall" : : "a"(1), "D"(status) : "rcx", "r11");
}

void sys_libc_log(const char *message) {

   int len = 0; 
   while(message[len])
        len++;

   asm volatile ("syscall" : : "a"(2), "D"(message), "S"(len) :"rcx", "r11");
}

[[noreturn, gnu::weak]] void sys_thread_exit() {
   sys_exit(0);
}

[[noreturn]] void sys_libc_panic() {
   sys_libc_log("MLIBC Panic !");
   sys_exit(-1);
}

int sys_futex_wait(int *pointer, int expected, const struct timespec *time) {
   int ret ;
   asm volatile ("syscall" : "=a"(ret) : "a"(3), "D"(pointer), "S"(expected) :"rcx", "r11");
   return ret;
}

int sys_futex_wake(int *pointer) {
   int ret;
   asm volatile ("syscall" : "=a"(ret) : "a"(4), "D"(pointer) :"rcx", "r11");
   return ret;
}

int sys_tcb_set(void *pointer) {
   int ret;
   asm volatile ("syscall" : "=a"(ret) : "a"(5), "D"(pointer) :"rcx", "r11");
   return ret;
}

int sys_open(const char *pathname, int flags, mode_t mode, int *fd) {
   int ret;
   asm volatile ("syscall" : "=a"(ret) : "a"(7), "D"(pathname), "S"(fd) :"rcx", "r11");
   return ret;
}

int sys_seek(int fd, off_t offset, int whence, off_t *new_offset) {
   int ret;
   asm volatile("syscall" : "=a"(ret), "=D"(new_offset) : "a"(8), "D"(fd), "S"(offset), "d"(whence): "rcx", "r11");
   return ret;
}

int sys_read(int fd, void *buf, size_t count, ssize_t *bytes_read) {
   int ret;
   asm volatile("syscall" : "=a"(ret), "=D"(bytes_read) : "a"(9), "D"(fd), "S"(buf), "d"(count): "rcx", "r11");
   return ret;
}

int sys_write(int fd, const void *buf, size_t count, ssize_t *bytes_written) {
   int ret;
   asm volatile("syscall" : "=a"(ret), "=D"(bytes_written) : "a"(10), "D"(fd), "S"(buf), "d"(count): "rcx", "r11");
   return ret;
}

int sys_close(int fd) {
   int ret;
   asm volatile("syscall" : "=a"(ret) : "a"(11) : "rcx", "r11");
   return ret;
}

int sys_vm_map(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window) {
   int ret;
   asm volatile("syscall" : "=a"(ret), "=D"(window) : "a"(12), "D"(hint), "S"(size) : "rcx", "r11");
   return ret;
}

int sys_vm_unmap(void *pointer, size_t size) {
   int ret;
   asm volatile("syscall" : "=a"(ret) : "a"(13), "D"(pointer), "S"(size) : "rcx", "r11");
   return ret;
}

int sys_anon_allocate(size_t size, void **pointer) {
   return sys_vm_map(0,size,0,0,0,0,pointer);
}

int sys_anon_free(void *pointer, size_t size) {
   return sys_vm_unmap(pointer,size);
}

int sys_clock_get(int clock, time_t *secs, long *nanos) {
   mlibc::infoLogger() << "TODO: Implement " << __func__ << frg::endlog;
   return 0;
}

}