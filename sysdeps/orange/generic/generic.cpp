#include <mlibc/all-sysdeps.hpp>
#include <mlibc/debug.hpp>
#include <errno.h>
#include <fcntl.h>

#include <unistd.h>

#include <sys/mman.h>

#include <stdio.h>
#include <string.h>

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
    register uint64_t r8 asm("r8") = mode;
    asm volatile("syscall" : "=a"(ret), "=d"(fd0) : "a"(3), "D"(dirfd), "S"(path), "d"(flags), "r"(r8) : "rcx","r11");
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

int sys_access(const char *path, int mode) {
   return 0;
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
    uint64_t timestamp;
    int ret;
    asm volatile("syscall" : "=a"(ret), "=d"(timestamp) : "a"(46) : "rcx","r11");
    *secs = timestamp / 1000000000;
    *nanos = timestamp % 1000000000;
    return ret;
}

int sys_stat(fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf) {
    int ready_fd = fd;

    if(fsfdt == fsfd_target::path || fsfdt == fsfd_target::fd_path) {
      int ret1 = sys_open(path,0,0,&ready_fd);
      if(ret1)
         return ret1;
    }

    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(13), "D"(ready_fd), "S"(statbuf), "d"(flags) : "rcx", "r11");

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
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(29), "D"(path), "S"(argv), "d"(envp): "rcx","r11");
    return ret; // error
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

int sys_fcntl(int fd, int request, va_list args, int *result) {
    uint64_t arg = va_arg(args,uint64_t);
    uint64_t result0;
    int ret;
    asm volatile("syscall" : "=a"(ret), "=d"(result0) : "a"(35), "D"(fd), "S"(request), "d"(arg) : "rcx","r11");
    *result = ret;
    return ret;
}

int sys_fsync(int fd) {
    return 0;
}

int sys_pselect(int num_fds, fd_set *read_set, fd_set *write_set,fd_set *except_set, const struct timespec *timeout, const sigset_t *sigmask, int *num_events) {
    return ENOSYS; 
}

int sys_sigprocmask(int how, const sigset_t *__restrict set, sigset_t *__restrict retrieve) {
    return 0;
}

int sys_sigaction(int, const struct sigaction *__restrict, struct sigaction *__restrict) {
    return 0;
}

int sys_uname(struct utsname *buf) {
    memcpy(buf->sysname, "Orange",6);
	memcpy(buf->nodename, "orange-pc",6);
	memcpy(buf->release, "\0",1);
	memcpy(buf->version, "\0",1);
#if defined(__x86_64__)
	memcpy(buf->machine, "x86_64",6);
#endif
    return 0;
}

int sys_fchdir(int fd) {
    int ret = 0;
    asm volatile("syscall" : "=a"(ret) : "a"(36), "D"(fd) : "rcx","r11");
    return ret;
}

int sys_chdir(const char *path) {
    int fd;
    int ret = sys_open(path,O_DIRECTORY,O_RDONLY,&fd);
    if(ret != 0)
        return ret;
    int ret0 = sys_fchdir(fd);
    sys_close(fd);
    return ret0;
}

int sys_sleep(time_t *secs, long *nanos) {
    long how_much = 0;
    time_t sec = *secs;
    long nano = *nanos;
    
    if(sec < 0)
        sec = 0;
    if(nano < 0)
        nano = 0;

    how_much = (sec * 1000 * 1000) + (nano / 1000);
    asm volatile("syscall" : : "a"(37), "D"(how_much) : "rcx","r11");
    return 0;
}

struct shitaddr {
	sa_family_t sun_family;
	char sun_path[108];
};

int sys_accept(int fd, int *newfd, struct sockaddr *addr_ptr, socklen_t *addr_length, int flags) {
    int ret;
    int newfd0;
    asm volatile("syscall" : "=a"(ret), "=d"(newfd0) : "a"(42), "D"(fd), "S"(addr_ptr), "d"(sizeof(struct shitaddr)) : "rcx","r11");
    if(addr_length)
        *addr_length = sizeof(struct shitaddr);
    if(newfd)
        *newfd = newfd0;
    return ret;
}

int sys_bind(int fd, const struct sockaddr *addr_ptr, socklen_t addr_length) {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(43), "D"(fd), "S"(addr_ptr), "d"(addr_length) : "rcx","r11");
    return ret;
}

int sys_connect(int fd, const struct sockaddr *addr_ptr, socklen_t addr_length) {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(41), "D"(fd), "S"(addr_ptr), "d"(addr_length) : "rcx","r11");
    return ret;
}

int sys_socket(int family, int type, int protocol, int *fd) {
    int ret;
    int newfd;
    asm volatile("syscall" : "=a"(ret), "=d"(newfd) : "a"(44), "D"(family), "S"(type), "d"(protocol) : "rcx","r11");
    *fd = newfd;
    return ret;
}

int sys_listen(int fd, int backlog) {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(45), "D"(fd), "S"(backlog) : "rcx","r11");
    return ret;
}

ssize_t sys_sendto(int fd, const void *buffer, size_t size, int flags, const struct sockaddr *sock_addr, socklen_t addr_length, ssize_t *length) {
    ssize_t written;
    int ret = sys_write(fd,buffer,size,&written);
    *length = written;
    return ret;
}

ssize_t sys_recvfrom(int fd, void *buffer, size_t size, int flags, struct sockaddr *sock_addr, socklen_t *addr_length, ssize_t *length) {
    ssize_t readen;
    int ret = sys_read(fd,buffer,size,&readen);
    *length = readen;
    return ret;
}

int sys_mkfifoat(int dirfd, const char *path, mode_t mode) {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(47), "D"(dirfd), "S"(path), "d"(mode) : "rcx","r11");
    return ret;
}

int sys_poll(struct pollfd *fds, nfds_t count, int timeout, int *num_events) {
    int ret;
    int num;
    asm volatile("syscall" : "=a"(ret), "=d"(num) : "a"(48), "D"(fds), "S"(count), "d"(timeout) : "rcx","r11");
    *num_events = num;
    return ret;
}

int sys_readlink(const char *path, void *buffer, size_t max_size, ssize_t *length) {
    return sys_readlinkat(AT_FDCWD,path,buffer,max_size,length);
}

int sys_readlinkat(int dirfd, const char *path, void *buffer, size_t max_size, ssize_t *length) {
    int ret;
    ssize_t len;
    register uint64_t r8 asm("r8") = max_size;
    asm volatile("syscall" : "=a"(ret), "=d"(len) : "a"(49), "D"(dirfd), "S"(path), "d"(buffer), "r"(r8) : "rcx", "r11");
    *length = len;
    return ret;
}

int sys_link(const char *old_path, const char *new_path) {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(50), "D"(old_path), "S"(new_path) : "rcx","r11");
    return ret;
}

int sys_unlinkat(int fd, const char *path, int flags) {
    return 0;
}

int sys_fchmod(int fd, mode_t mode) {
    return 0;
}

int sys_mkdir(const char *path, mode_t mode) {
    return sys_mkdirat(AT_FDCWD,path,mode);
}

int sys_mkdirat(int dirfd, const char *path, mode_t mode) {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(51), "D"(dirfd), "S"(path), "d"(mode) : "rcx","r11");
    return ret;
}

int sys_chmod(const char *pathname, mode_t mode) {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(52), "D"(pathname), "S"(mode) : "rcx","r11");
    return ret;
}

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
			return EFAULT;
		}
	}

	unsigned long long* sp =
	    (unsigned long long*)((unsigned long long)(*stack_base) + *stack_size);

	*--sp = (unsigned long long)(tcb);
	*--sp = (unsigned long long)(user_arg);
	*--sp = (unsigned long long)(entry);
	*stack =(void*)(sp);
	return 0;
}

extern "C" void __mlibc_start_thread();

int sys_clone(void *tcb, pid_t *pid_out, void *stack) { 
    int pid;
    int ret;
    uint64_t entry = (uint64_t)__mlibc_start_thread;
    asm volatile("syscall" : "=a"(ret), "=D"(pid) : "a"(54), "D"(stack) , "S"(entry), "d"(0) : "rcx","r11");
    *pid_out = pid;
    return ret;
}

}