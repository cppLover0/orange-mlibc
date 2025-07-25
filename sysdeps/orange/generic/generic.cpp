#include <mlibc/all-sysdeps.hpp>
#include <mlibc/debug.hpp>
#include <errno.h>
#include <fcntl.h>

namespace mlibc {

int sys_futex_wake(int *pointer) {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(1), "D"(pointer) : "rcx","r11");
    return ret;
}

int sys_futex_wait(int *pointer, int expected, const struct timespec *time) {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(2), "D"(pointer), "S"(expected) : "rcx","r11");
    return ret;
}

int sys_openat(int dirfd, const char *path, int flags, mode_t mode, int *fd) {
    int fd0;
    int ret;
    asm volatile("syscall" : "=a"(ret), "=d"(fd0) : "a"(3), "D"(dirfd), "S"(path), "d"(flags) : "rcx","r11");
    *fd = fd0;
    return ret;
}

int sys_open(const char *pathname, int flags, mode_t mode, int *fd) {
    int fd0;
    int ret;
    ret = sys_openat(AT_FDCWD,pathname,flags,mode,&fd0);
    *fd = fd0;
    return ret;
}

int sys_read(int fd, void *buf, size_t count, ssize_t *bytes_read) {
    int ret;
    int64_t br;
    asm volatile("syscall" : "=a"(ret), "=d"(br) : "a"(4), "D"(fd), "S"(buf), "d"(count) : "rcx","r11");
    *bytes_read = br;
    return ret;
}

int sys_write(int fd, const void *buf, size_t count, ssize_t *bytes_written) {
    int ret;
    int64_t bw;
    asm volatile("syscall" : "=a"(ret), "=d"(bw) : "a"(5), "D"(fd), "S"(buf), "d"(count) : "rcx","r11");
    *bytes_written =bw;
    return ret;
}

int sys_seek(int fd, off_t offset, int whence, off_t *new_offset) {
    int ret;
    int64_t new_offset0;
    asm volatile("syscall" : "=a"(ret), "=d"(new_offset0) : "a"(6), "D"(fd), "S"(offset), "d"(whence) : "rcx","r11");
    *new_offset = new_offset0;
    return ret;
}

int sys_close(int fd) {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(7), "D"(fd) : "rcx","r11");
    return ret;
}

int sys_tcb_set(void *pointer) {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(8), "D"(pointer) : "rcx","r11");
    return ret;
}

void sys_libc_log(const char *message) {
    asm volatile("syscall" : : "a"(9), "D"(message) : "rcx","r11");
}

void sys_exit(int status) {
    asm volatile("syscall" : : "a"(10), "D"(status) : "rcx","r11");
}

void sys_libc_panic() {
    sys_libc_log("mlibc panic\n");
    sys_exit(-1);
}

int sys_vm_map(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window) {
    register uint64_t r8 asm("r8") = flags;
    uint64_t result;
    int ret;
    asm volatile("syscall" : "=a"(ret), "=d"(result) : "a"(11), "D"(hint), "S"(size), "d"(fd), "r"(r8) : "rcx","r11");
    *window = (void*)result;
    return ret;
}

int sys_vm_unmap(void *pointer, size_t size) {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(12), "D"(pointer), "S"(size) : "rcx","r11");
    return ret;
}

int sys_anon_allocate(size_t size, void **pointer) {
    return sys_vm_map(0,size,0,MAP_ANONYMOUS,-1,0,pointer);
}

int sys_anon_free(void *pointer, size_t size) {
    return sys_vm_unmap(pointer,size);
}

[[gnu::weak]] int sys_stat(fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf) {
    int ready_fd = fd;

   if(fsfdt == fsfd_target::path || fsfdt == fsfd_target::fd_path) {
      int ret1 = sys_open(path,0,0,&ready_fd);
      if(ret1)
         return ret1;
   }

   int ret;
   asm volatile("syscall" : "=a"(ret) : "a"(13), "D"(ready_fd), "S"(statbuf) : "rcx", "r11");

   if(fsfdt == fsfd_target::path || fsfdt == fsfd_target::fd_path)
      sys_close(ready_fd);
}

[[gnu::weak]] int sys_vm_protect(void *pointer, size_t size, int prot) {
    return 0;
}

}