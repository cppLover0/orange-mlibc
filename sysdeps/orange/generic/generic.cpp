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

int sys_clock_get(int clock, time_t *secs, long *nanos) {
    return ENOSYS;
}

int sys_stat(fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf) {
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

    return ret;
}

int sys_vm_protect(void *pointer, size_t size, int prot) {
    return 0;
}

int sys_pipe(int *fds, int flags) {
    int read_fd;
    int write_fd;
    asm volatile ("syscall" : "=a"(read_fd), "=d"(write_fd) : "a"(14), "D"(flags) : "rcx","r11");
    fds[0] = read_fd;
    fds[1] = write_fd;
    return 0;
}

int sys_fork(pid_t *child) {
    int new_pid;
    int ret;
    asm volatile("syscall" : "=a"(ret), "=d"(new_pid) : "a"(15) : "rcx","r11");
    *child = new_pid;
    return ret;
}

int sys_dup(int fd, int flags, int *newfd) {
    int fd0;
    int ret;
    asm volatile("syscall" : "=a"(ret), "=d"(fd0) : "a"(16), "D"(fd), "S"(flags) : "rcx","r11");
    *newfd = fd0;
    return ret;
}

int sys_dup2(int fd, int flags, int newfd) {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(17), "D"(fd), "S"(flags), "d"(newfd) : "rcx","r11");
    return ret;
}

int sys_ioctl(int fd, unsigned long request, void *arg, int *result) {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(20), "D"(fd), "S"(request), "d"(arg) : "rcx","r11");
    *result = ret;
    return ret;
}

int sys_isatty(int fd) {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(23), "D"(fd) : "rcx","r11");
    return ret;
}

int sys_ptsname(int fd, char *buffer, size_t length) {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(26), "D"(fd), "S"(buffer), "d"(length) : "rcx","r11");
    return ret;
}

int sys_unlockpt(int fd) {
    return 0;
}

int sys_open_dir(const char *path, int *handle) {
    int fd;
    int ret = sys_openat(AT_FDCWD,path,O_DIRECTORY,O_RDWR,&fd);
    *handle = fd;
    return ret;
}

int sys_read_entries(int handle, void *buffer, size_t max_size, size_t *bytes_read) {
    int br;
    int ret;
    asm volatile("syscall" : "=a"(ret), "=d"(br) : "a"(28), "D"(handle), "S"(buffer) : "rcx","r11");
    *bytes_read = br;
    return ret;
}

int sys_tcgetattr(int fd, struct termios *attr){
	int res;
	return sys_ioctl(fd, 0x5401, (void *)attr, &res);
}

int sys_tcsetattr(int fd, int no, const struct termios *attr){
	int res;
	return sys_ioctl(fd, 0x5402, (void *)attr, &res);
}

int sys_execve(const char *path, char *const argv[], char *const envp[]) {
    asm volatile("syscall" : : "a"(29), "D"(path), "S"(argv), "d"(envp): "rcx","r11");
}

gid_t sys_getgid() {
   return 0;
}

gid_t sys_getegid() {
   return 0;
}

uid_t sys_getuid() {
   return 0;
}

uid_t sys_geteuid() {
   return 0;
}

pid_t sys_gettid() {
   return 0;
}

pid_t sys_getppid() {
   int ret;
   asm volatile("syscall" : "=a"(ret) : "a"(31) : "rcx", "r11");
   return ret;
}

pid_t sys_getpid() {
   int ret;
   asm volatile("syscall" : "=a"(ret) : "a"(30) : "rcx", "r11");
   return ret;
}

int sys_getpgid(pid_t pid, pid_t *pgid) {
   return 0;
}

int sys_getsid(pid_t pid, pid_t *sid) {
   return 0;
}

int sys_setpgid(pid_t pid, pid_t pgid) {
   return 0;
}

int sys_setuid(uid_t uid) {
   return 0;
}

int sys_seteuid(uid_t euid) {
   return 0;
}

int sys_setgid(gid_t gid) {
   return 0;
}

int sys_setegid(gid_t egid) {
   return 0;
}

int sys_sigprocmask(int how, const sigset_t *__restrict set, sigset_t *__restrict retrieve) {
    return 0;
}

int sys_sigaction(int, const struct sigaction *__restrict, struct sigaction *__restrict) {
    return 0;
}

int sys_gethostname(char *buffer, size_t bufsize) {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(32), "D"(buffer), "S"(bufsize) : "rcx","r11");
    return ret;
}

int sys_getcwd(char *buffer, size_t size) {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(33), "D"(buffer), "S"(size) : "rcx","r11");
    return ret;
}

int sys_waitpid(pid_t pid, int *status, int flags, struct rusage *ru, pid_t *ret_pid) {
    int ret;
    uint64_t final;
    int status0;
    int retpid;
    asm volatile("syscall" : "=a"(ret), "=d"(final) : "a"(34), "D"(pid) : "rcx","r11");
    status0 = final >> 32;
    retpid = final & 0xFFFFFFFF;
    *status = status0;
    *ret_pid = retpid;
    return ret;
}

}