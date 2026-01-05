#include <bits/ensure.h>
#include <mlibc/debug.hpp>
#include <mlibc/all-sysdeps.hpp>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <asm/ioctls.h>
#include <poll.h>
#include <sys/select.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

namespace mlibc {

int sys_futex_wake(int *pointer) {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(1), "D"(pointer) : "rcx","r11");
    return ret;
}

int sys_futex_wait(int *pointer, int expected, const struct timespec *time) {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(2), "D"(pointer), "S"(expected), "d"(time) : "rcx","r11");
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

void sys_thread_exit() {
    sys_exit(0);
}

int sys_thread_setname(void *tcb, const char *name) {
    mlibc::infoLogger() << "The name of this thread is " << name << frg::endlog;
    return 0;
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
   uid_t user;
   asm volatile("syscall" : "=a"(user) : "a"(67) : "rcx","r11");
   return user;
}

int sys_setuid(uid_t uid) {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(68), "D"(uid) : "rcx","r11");
    return ret;
}

uid_t sys_geteuid() {
   return 0;
}

pid_t sys_gettid() {
   return sys_getpid();
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

int sys_sockname(int fd, struct sockaddr *addr_ptr, socklen_t max_addr_length, socklen_t *actual_length) {
    socklen_t len;
    int ret;
    asm volatile("syscall" : "=a"(ret), "=d"(len) : "a"(69), "D"(fd), "S"(addr_ptr), "d"(max_addr_length) : "rcx","r11");
    *actual_length = len;
    return ret;
}

int sys_waitpid(pid_t pid, int *status, int flags, struct rusage *ru, pid_t *ret_pid) {
    int ret;
    uint64_t final;
    int status0;
    int retpid;
    asm volatile("syscall" : "=a"(ret), "=d"(final) : "a"(34), "D"(pid), "S"(flags) : "rcx","r11");
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

int sys_msg_send(int fd, const struct msghdr *hdr, int flags, ssize_t *length) {
    ssize_t total_written = 0;
    int ret = 0;
    asm volatile("syscall" : "=a"(ret), "=d"(total_written) : "a"(71), "D"(fd), "S"(hdr), "d"(flags) : "rcx","r11");
    *length = total_written;
    return ret;
}

int sys_msg_recv(int fd, struct msghdr *hdr, int flags, ssize_t *length) {
    ssize_t total_read = 0;
    int ret = 0;
    asm volatile("syscall" : "=a"(ret), "=d"(total_read) : "a"(73), "D"(fd), "S"(hdr), "d"(flags) : "rcx","r11");
    *length = total_read;
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

#ifndef MLIBC_BUILDING_RTLD

// tbh i used astral sysdep just cuz i dont have idea how select() works
int sys_pselect(int num_fds, fd_set *read_set, fd_set *write_set, fd_set *except_set, const struct timespec *timeout, const sigset_t *sigmask, int *num_events) {
	pollfd *fds = (pollfd *)malloc(num_fds * sizeof(pollfd));

	if(fds == NULL)
			return ENOMEM;

	int actual_count = 0;

	for(int fd = 0; fd < num_fds; ++fd) {
		short events = 0;
		if(read_set && FD_ISSET(fd, read_set)) {
			events |= POLLIN;
		}

		if(write_set && FD_ISSET(fd, write_set)) {
			events |= POLLOUT;
		}

		if(except_set && FD_ISSET(fd, except_set)) {
			events |= POLLIN;
		}

		if(events) {
			fds[actual_count].fd = fd;
			fds[actual_count].events = events;
			fds[actual_count].revents = 0;
			actual_count++;
		}
	}

	int num;
	int err;

    if(timeout) {
        err = sys_poll(fds, actual_count, (timeout->tv_sec * 1000) + (timeout->tv_nsec / (1000 * 1000)), &num);
    } else {
        err = sys_poll(fds, actual_count, -1, &num);
    }

	if(err) {
		free(fds);
		return err;
	}

	#define READ_SET_POLLSTUFF (POLLIN | POLLHUP | POLLERR)
	#define WRITE_SET_POLLSTUFF (POLLOUT | POLLERR)
	#define EXCEPT_SET_POLLSTUFF (POLLPRI)

	int return_count = 0;
	for(int fd = 0; fd < actual_count; ++fd) {
		int events = fds[fd].events;
		if((events & POLLIN) && (fds[fd].revents & READ_SET_POLLSTUFF) == 0) {
			FD_CLR(fds[fd].fd, read_set);
			events &= ~POLLIN;
		}

		if((events & POLLOUT) && (fds[fd].revents & WRITE_SET_POLLSTUFF) == 0) {
			FD_CLR(fds[fd].fd, write_set);
			events &= ~POLLOUT;
		}

		if(events)
			return_count++;
	}
	*num_events = return_count;
	free(fds);
	return 0;
}

#endif

int sys_fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags) {
    return 0;
}

int sys_ttyname(int fd, char *buf, size_t size) {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(56), "D"(fd), "S"(buf), "d"(size) : "rcx","r11");
    return ret;
}

int sys_sigprocmask(int how, const sigset_t *__restrict set, sigset_t *__restrict retrieve) {
    return 0;
}

int sys_sigaction(int, const struct sigaction *__restrict, struct sigaction *__restrict) {
    return 0;
}

int sys_setpriority(int which, id_t who, int prio) {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(59), "D"(which), "S"(who), "d"(prio) : "rcx", "r11");
    return ret;
}

int sys_getpriority(int which, id_t who, int *value) {
    int ret;
    int val;
    asm volatile("syscall" : "=a"(ret), "=d"(val) : "a"(60), "D"(which), "S"(who) : "rcx", "r11");
    *value = val;
    return ret;
}

void sys_yield() {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(61) : "rcx", "r11");
}

int sys_rename(const char *path, const char *new_path) {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(62), "D"(path), "S"(new_path) : "rcx","r11");
    return ret;
}

int sys_socketpair(int domain, int type_and_flags, int proto, int *fds) {
    int fd0;
    int fd1;
    asm volatile("syscall" : "=a"(fd0), "=d"(fd1) : "a"(66), "D"(domain), "S"(type_and_flags), "d"(proto) : "rcx","r11");
    fds[0] = fd0;
    fds[1] = fd1;
    return 0;
}

int sys_getsockopt(int fd, int layer, int number,void *__restrict buffer, socklen_t *__restrict size) {
    register uint64_t r8 asm("r8") = (uint64_t)buffer;
    uint64_t ret;
    socklen_t len;
    asm volatile("syscall" : "=a"(ret), "=d"(len) : "a"(70), "D"(fd), "S"(layer), "d"(number), "r"(r8) : "rcx","r11");
    *size = len;
    return ret;
}

int sys_eventfd_create(unsigned int initval, int flags, int *fd) {
    int ret;
    int fd0;
    asm volatile("syscall" : "=a"(ret), "=d"(fd0) : "a"(72), "D"(initval), "S"(flags) : "rcx","r11");
    *fd = fd0;
    return ret;
}

int sys_kill(int pid, int sig) {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(74), "D"(pid), "S"(sig) : "rcx","r11");
    return ret;
}

int sys_shutdown(int sockfd, int how) {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(75), "D"(sockfd) : "rcx","r11");
    return ret;
}

int sys_shmget(int *shm_id, key_t key, size_t size, int shmflg) {
    int ret;
    int new_id;
    asm volatile("syscall" : "=a"(ret), "=d"(new_id) : "a"(76), "D"(key), "S"(size), "d"(shmflg) : "rcx","r11");
    *shm_id = new_id;
    return ret;
}

int sys_shmat(void **seg_start, int shmid, const void *shmaddr, int shmflg) {
    void* seg;
    int ret;
    asm volatile("syscall" : "=a"(ret), "=d"(seg) : "a"(77), "D"(shmid), "S"(shmaddr), "d"(shmflg) : "rcx","r11");
    *seg_start = seg;
    return ret;
}

int sys_shmdt(const void *shmaddr) {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(78), "D"(shmaddr) : "rcx","r11");
    return ret;
}

int sys_shmctl(int *idx, int shmid, int cmd, struct shmid_ds *buf) {
    int ret;
    asm volatile("syscall" : "=a"(ret) : "a"(79), "D"(shmid), "S"(cmd), "d"(buf) : "rcx","r11");
    return ret;
}

int sys_setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value) {
    return ENOSYS;
}

int sys_getresuid(uid_t *ruid, uid_t *euid, uid_t *suid) {
    *ruid = sys_getuid();
    *euid = sys_getuid();
    *suid = sys_getuid();
}

}