/*
 * Ephemeral CI LD_PRELOAD for the re-signed x86 shell.
 *
 * - kill/tgkill/raise: anti-tamper self-termination (PLT)
 * - setuid/setgid family: WrapperInit AssetManager idmap (seccomp SIGSYS)
 * - syscall(): shell bypasses PLT kill/exit via libc syscall()
 * - _exit/_Exit: return instead of terminating (do NOT pause — freezes boot)
 * - seccomp-bpf constructor: block raw syscall insn for kill/exit_group
 *   (UPX-packed shell issues these directly after unpack; PLT patches miss them)
 *
 * Built on the Actions NDK runner; never ships to users.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <grp.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

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

#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER 2
#endif
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

static int is_deadly_nr(long number) {
  return number == SYS_kill || number == SYS_tkill || number == SYS_tgkill
      || number == SYS_exit || number == SYS_exit_group;
}

/* Install a process-wide filter that turns deadly syscalls into errno=0
 * no-ops. Covers UPX-unpacked direct `syscall` instructions that never
 * hit PLT or the libc syscall() wrapper.
 */
/* Anti-tamper after a blocked self-kill often raises SIGILL/SIGTRAP in
 * anonymous (UPX) code. Swallow those so attachBaseContext can continue.
 * SIGKILL cannot be caught — seccomp must keep blocking it.
 */
static void ignore_signal(int sig) {
  (void)sig;
}

static void install_signal_guards(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = ignore_signal;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  sigaction(SIGILL, &sa, NULL);
  sigaction(SIGTRAP, &sa, NULL);
  sigaction(SIGABRT, &sa, NULL);
  sigaction(SIGBUS, &sa, NULL);
  sigaction(SIGFPE, &sa, NULL);
  sigaction(SIGSYS, &sa, NULL);
  sigaction(SIGPIPE, &sa, NULL);
}

static void install_seccomp_guard(void) __attribute__((constructor(101)));
static void install_seccomp_guard(void) {
  install_signal_guards();

  struct sock_filter filter[] = {
      /* 0: load arch */
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
      /* 1: allow only x86_64 */
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
      /* 2: bad arch -> allow (don't brick the process) */
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /* 3: load nr */
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
      /* 4.. : deadly -> ERRNO(0) */
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit_group, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_kill, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_tgkill, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_tkill, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = filter,
  };

  /* Best-effort: failure must not prevent the rest of the preload. */
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    return;
  }
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
    /* Some emulators already have a filter; try syscall form with TSYNC. */
#ifdef __NR_seccomp
    syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
            1 /* SECCOMP_FILTER_FLAG_TSYNC */, &prog);
#endif
  }
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

/* Direct _exit bypasses atexit and our exit() PLT patch.
 * Must NOT block: a forever-pause freezes WrapperInit on the main
 * thread and the shell never reaches attachBaseContext.
 */
void _exit(int status) {
  (void)status;
}

void _Exit(int status) {
  (void)status;
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
