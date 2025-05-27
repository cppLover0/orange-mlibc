#include <mlibc/all-sysdeps.hpp>
#include <mlibc/debug.hpp>
#include <errno.h>

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
   asm volatile ("syscall" : "=a"(ret) : "a"(7), "D"(pathname), "S"(fd), "d"(flags) :"rcx", "r11");
   return ret;
}

int sys_seek(int fd, off_t offset, int whence, off_t *new_offset) {
   int ret;
   long no = 0;
   asm volatile("syscall" : "=a"(ret), "=d"(no) : "a"(8), "D"(fd), "S"(offset), "d"(whence): "rcx", "r11");
   *new_offset = no;
   return ret;
}

int sys_read(int fd, void *buf, size_t count, ssize_t *bytes_read) {
   int ret;
   long br = 0;
   asm volatile("syscall" : "=a"(ret), "=d"(br) : "a"(9), "D"(fd), "S"(buf), "d"(count): "rcx", "r11");
   *bytes_read = br;
   return ret;
}

int sys_write(int fd, const void *buf, size_t count, ssize_t *bytes_written) {
   int ret;
   long bw = 0;
   asm volatile("syscall" : "=a"(ret), "=d"(bw) : "a"(10), "D"(fd), "S"(buf), "d"(count): "rcx", "r11");
   *bytes_written = bw;
   return ret;
}

int sys_close(int fd) {
   int ret;
   asm volatile("syscall" : "=a"(ret) : "a"(11) : "rcx", "r11");
   return ret;
}

int sys_vm_map(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window) {
   int ret;
   void* p = 0;
   asm volatile("syscall" : "=a"(ret), "=d"(p) : "a"(12), "D"(hint), "S"(size) : "rcx", "r11");
   *window = p;
   return ret;
}

int sys_vm_unmap(void *pointer, size_t size) {
   int ret;
   asm volatile("syscall" : "=a"(ret) : "a"(13), "D"(pointer), "S"(size) : "rcx", "r11");
   return ret;
}

int sys_anon_allocate(size_t size, void **pointer) {
   int ret;
   void* p = 0;
   asm volatile("syscall" : "=a"(ret), "=d"(p) : "a"(12), "D"(0), "S"(size) : "rcx", "r11");
   *pointer = p;
   return ret;
}

int sys_anon_free(void *pointer, size_t size) {
   int ret;
   asm volatile("syscall" : "=a"(ret) : "a"(13), "D"(pointer), "S"(size) : "rcx", "r11");
   return ret;
}

[[gnu::weak]] int sys_stat(fsfd_target fsfdt, int fd, const char *path, int flags,struct stat *statbuf)  {

   int ready_fd = fd;

   if(fsfdt == fsfd_target::path) {
      int ret1 = sys_open(path,0,0,&ready_fd);
      if(ret1)
         return ret1;
   }

   int ret;
   asm volatile("syscall" : "=a"(ret) : "a"(23), "D"(ready_fd), "S"(statbuf) : "rcx", "r11");

   if(fsfdt == fsfd_target::path)
      sys_close(ready_fd);

   return ret;
}

[[gnu::weak]] int sys_vm_protect(void *pointer, size_t size, int prot) {
   //mlibc::infoLogger() << "TODO: Implement " << __func__ << frg::endlog;
   return 0;
}

[[gnu::weak]] int sys_isatty(int fd) {
   int ret;
   asm volatile("syscall" : "=a"(ret) : "a"(14), "D"(fd) : "rcx", "r11");
   return ret;
}

[[gnu::weak]] pid_t sys_getpid() {
   int ret;
   asm volatile("syscall" : "=a"(ret) : "a"(17) : "rcx", "r11");
   return ret;
}

[[gnu::weak]] int sys_fork(pid_t *child) {
   int ret;
   pid_t p = 0;
   asm volatile("syscall" : "=a"(ret), "=d"(p) : "a"(15) : "rcx", "r11");
   //mlibc::infoLogger() << "New pid: " << mlibc::sys_getpid() << frg::endlog;
   *child = p;
   return ret;
}

[[gnu::weak]] int sys_execve(const char *path, char *const argv[], char *const envp[]) {
   asm volatile("syscall" : : "a"(19), "D"(path), "S"(argv), "d"(envp) : "rcx", "r11");
}

int sys_clock_get(int clock, time_t *secs, long *nanos) {
   //mlibc::infoLogger() << "TODO: Implement " << __func__ << frg::endlog;
   return ENOSYS;
}

[[gnu::weak]] gid_t sys_getgid() {
   return 0;
}

[[gnu::weak]] gid_t sys_getegid() {
   return 0;
}

[[gnu::weak]] uid_t sys_getuid() {
   return 0;
}

[[gnu::weak]] uid_t sys_geteuid() {
   return 0;
}

[[gnu::weak]] pid_t sys_gettid() {
   return 0;
}
[[gnu::weak]] pid_t sys_getppid() {
   int ret;
   asm volatile("syscall" : "=a"(ret) : "a"(21) : "rcx", "r11");
   return ret;
}

[[gnu::weak]] int sys_getpgid(pid_t pid, pid_t *pgid) {
   return 0;
}

[[gnu::weak]] int sys_getsid(pid_t pid, pid_t *sid) {
   return 0;
}

[[gnu::weak]] int sys_setpgid(pid_t pid, pid_t pgid) {
   return 0;
}

[[gnu::weak]] int sys_setuid(uid_t uid) {
   return 0;
}

[[gnu::weak]] int sys_seteuid(uid_t euid) {
   return 0;
}

[[gnu::weak]] int sys_setgid(gid_t gid) {
   return 0;
}

[[gnu::weak]] int sys_setegid(gid_t egid) {
   return 0;
}

[[gnu::weak]] int sys_sigprocmask(int how, const sigset_t *__restrict set, sigset_t *__restrict retrieve) {
   //mlibc::infoLogger() << "TODO: Implement " << __func__ << frg::endlog;
   return 0;   
}

[[gnu::weak]] int sys_sigaction(int, const struct sigaction *__restrict, struct sigaction *__restrict) {
   //mlibc::infoLogger() << "TODO: Implement " << __func__ << frg::endlog;
   return 0;
}

[[gnu::weak]] int sys_gethostname(char *buffer, size_t bufsize) {
   int ret;
   asm volatile("syscall" : "=a"(ret) : "a"(22), "D"(buffer), "S"(bufsize) : "rcx", "r11");
   return ret;
}

[[gnu::weak]] int sys_ioctl(int fd, unsigned long request, void *arg, int *result) {
   int ret;
   asm volatile("syscall" : "=a"(ret) : "a"(26), "D"(fd), "S"(request), "d"(arg) : "rcx", "r11");
   *result = ret;
   return 0;
}

[[gnu::weak]] int sys_tcgetattr(int fd, struct termios *attr){
	int res;
	return sys_ioctl(fd, 0x5401, (void *)attr, &res);
}

[[gnu::weak]] int sys_tcsetattr(int fd, int no, const struct termios *attr){
	int res;
	return sys_ioctl(fd, 0x5402, (void *)attr, &res);
}

[[gnu::weak]] int sys_fcntl(int fd, int request, va_list args, int *result) {
   mlibc::infoLogger() << "TODO: Implement " << __func__ << frg::endlog;
   return ENOSYS;
}

[[gnu::weak]] int sys_dup(int fd, int flags, int *newfd) {
   int ret;
   int newfd1 = 0;
   asm volatile("syscall" : "=a"(ret), "=d"(newfd1): "a"(24), "D"(fd) : "rcx", "r11");
   *newfd = newfd1;
   return ret;
}

int sys_dup2(int fd, int flags, int newfd) {
   int ret;
   asm volatile("syscall" : "=a"(ret) : "a"(28), "D"(fd), "S"(newfd));
   return ret;
}

int sys_kill(int pid, int sig) {
   int ret;
   asm volatile("syscall" : "=a"(ret) : "a"(25), "D"(pid), "S"(sig) : "rcx", "r11");
   return ret;
}

[[gnu::weak]] int sys_waitpid(pid_t pid, int *status, int flags, struct rusage *ru, pid_t *ret_pid) {

   int ret;
   int ret_status;
   asm volatile("syscall" : "=a"(ret), "=d"(ret_status) : "a"(27), "D"(pid), "S"(ret_pid) : "rcx", "r11");

   *status = ret_status;
   
   return ret;

}

[[gnu::weak]] int sys_getcwd(char *buffer, size_t size) {
   
}

}