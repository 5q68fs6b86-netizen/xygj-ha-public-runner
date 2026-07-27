/*
 * Ephemeral CI LD_PRELOAD for the re-signed x86 shell.
 *
 * - kill/tgkill/raise: anti-tamper self-termination
 * - setuid/setgid family: WrapperInit AssetManager idmap (seccomp SIGSYS)
 * - syscall(): shell bypasses PLT kill/exit via raw syscall numbers
 *
 * Built on the Actions NDK runner; never ships to users.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <grp.h>

#ifndef SYS_kill
#define SYS_kill 62
#endif
#ifndef SYS_tkill
#define SYS_tkill 200
#endif
#ifndef SYS_tgkill
#define SYS_tgkill 234
#endif
#ifndef SYS_exit
#define SYS_exit 60
#endif
#ifndef SYS_exit_group
#define SYS_exit_group 231
#endif

static int is_deadly_nr(long number) {
  return number == SYS_kill || number == SYS_tkill || number == SYS_tgkill
      || number == SYS_exit || number == SYS_exit_group;
}

int kill(pid_t pid, int sig) {
  (void)pid;
  (void)sig;
  return 0;
}

int tgkill(int tgid, int tid, int sig) {
  (void)tgid;
  (void)tid;
  (void)sig;
  return 0;
}

int tkill(int tid, int sig) {
  (void)tid;
  (void)sig;
  return 0;
}

int pthread_kill(pthread_t thread, int sig) {
  (void)thread;
  (void)sig;
  return 0;
}

int raise(int sig) {
  (void)sig;
  return 0;
}

int setgid(gid_t gid) {
  (void)gid;
  return 0;
}

int setuid(uid_t uid) {
  (void)uid;
  return 0;
}

int setegid(gid_t gid) {
  (void)gid;
  return 0;
}

int seteuid(uid_t uid) {
  (void)uid;
  return 0;
}

int setregid(gid_t rgid, gid_t egid) {
  (void)rgid;
  (void)egid;
  return 0;
}

int setreuid(uid_t ruid, uid_t euid) {
  (void)ruid;
  (void)euid;
  return 0;
}

int setresgid(gid_t rgid, gid_t egid, gid_t sgid) {
  (void)rgid;
  (void)egid;
  (void)sgid;
  return 0;
}

int setresuid(uid_t ruid, uid_t euid, uid_t suid) {
  (void)ruid;
  (void)euid;
  (void)suid;
  return 0;
}

int setgroups(size_t size, const gid_t *list) {
  (void)size;
  (void)list;
  return 0;
}

typedef long (*real_syscall_t)(long, ...);

long syscall(long number, ...) {
  if (is_deadly_nr(number)) {
    return 0;
  }

  real_syscall_t real = (real_syscall_t)dlsym(RTLD_NEXT, "syscall");
  if (!real) {
    return -1;
  }

  va_list ap;
  va_start(ap, number);
  long a1 = va_arg(ap, long);
  long a2 = va_arg(ap, long);
  long a3 = va_arg(ap, long);
  long a4 = va_arg(ap, long);
  long a5 = va_arg(ap, long);
  long a6 = va_arg(ap, long);
  va_end(ap);
  return real(number, a1, a2, a3, a4, a5, a6);
}
