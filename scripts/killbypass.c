/*
 * Ephemeral CI LD_PRELOAD for the re-signed x86 shell.
 *
 * - kill/tgkill/raise: anti-tamper self-termination (PLT)
 * - setuid/setgid family: WrapperInit AssetManager idmap (seccomp SIGSYS)
 * - syscall(): shell bypasses PLT kill/exit via libc syscall()
 * - _exit/_Exit: return instead of terminating (do NOT pause — freezes boot)
 * - seccomp-bpf constructor: block raw syscall insn for kill/exit_group
 * - SIGSEGV (lazy): after kill is blocked the UPX shell null-derefs in
 *   anonymous code (fault 0x2c8/0x358). Retarget the null base register at
 *   a RW fake object and re-execute. Handler is installed AFTER WrapperInit
 *   preload so framework code is not disturbed; unfixable faults restore
 *   SIG_DFL (no RIP-skip — that caused multi-second fault storms).
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
#include <stdint.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/ucontext.h>
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

/* Large enough for the observed null-page offsets (0x2c8..0x358). */
static unsigned char g_fake_obj[0x2000];
static volatile int g_segv_installed = 0;
static volatile unsigned long g_sig_fix = 0;
static volatile unsigned long g_sig_fixed = 0;
static volatile unsigned long g_sig_fatal = 0;
static volatile int g_in_fatal_raise = 0;

static int fix_null_base_reg(ucontext_t *uc, void *fault_addr) {
  uintptr_t fault = (uintptr_t)fault_addr;
  /* Only classical null-page derefs from the UPX anti-tamper path. */
  if (fault >= 0x1000ul) {
    return 0;
  }

  const int regs[] = {
      REG_RAX, REG_RBX, REG_RCX, REG_RDX, REG_RSI, REG_RDI,
      REG_R8,  REG_R9,  REG_R10, REG_R11, REG_R12, REG_R13,
      REG_R14, REG_R15, REG_RBP,
  };

  for (size_t i = 0; i < sizeof(regs) / sizeof(regs[0]); i++) {
    greg_t *slot = &uc->uc_mcontext.gregs[regs[i]];
    uintptr_t base = (uintptr_t)(*slot);
    if (base < 0x1000ul && fault >= base && (fault - base) < sizeof(g_fake_obj)) {
      *slot = (greg_t)(uintptr_t)g_fake_obj;
      return 1;
    }
  }
  return 0;
}

static void crash_guard(int sig, siginfo_t *si, void *ctx) {
  ucontext_t *uc = (ucontext_t *)ctx;
  g_sig_fix++;

  if ((sig == SIGSEGV || sig == SIGBUS) &&
      fix_null_base_reg(uc, si ? si->si_addr : NULL)) {
    g_sig_fixed++;
    return; /* re-execute with non-null base */
  }

  /* Unfixable: restore default disposition and re-raise so this thread
   * dies cleanly instead of spinning (RIP+4 caused 50s preload storms). */
  g_sig_fatal++;
  signal(sig, SIG_DFL);
  g_in_fatal_raise = 1;
  raise(sig);
  g_in_fatal_raise = 0;
}

static void install_crash_guards_now(void) {
  if (g_segv_installed) {
    return;
  }
  g_segv_installed = 1;

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = crash_guard;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO | SA_RESTART;
  /* Only the faults the UPX shell raises after a blocked self-kill. */
  sigaction(SIGSEGV, &sa, NULL);
  sigaction(SIGBUS, &sa, NULL);
  sigaction(SIGILL, &sa, NULL);
  sigaction(SIGTRAP, &sa, NULL);
}

/* WrapperInit runs zygote preload inside the app process. Installing a
 * SIGSEGV handler that early turns framework faults into multi-second
 * storms. Defer until after preload, or on first anti-tamper kill. */
static void *deferred_guard_thread(void *arg) {
  (void)arg;
  /* PreloadClasses ~1-2s, PreloadResources normally <100ms; budget 3s. */
  usleep(3000 * 1000);
  install_crash_guards_now();
  return NULL;
}

static void ensure_crash_guards(void) {
  /* Fast path used from kill hooks — shell is already past preload. */
  install_crash_guards_now();
}

/* Soft signal swallowers for non-SEGV anti-tamper (installed early, cheap). */
static void ignore_signal(int sig) {
  (void)sig;
}

static void install_early_signal_ignores(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = ignore_signal;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  sigaction(SIGABRT, &sa, NULL);
  sigaction(SIGFPE, &sa, NULL);
  sigaction(SIGSYS, &sa, NULL);
  sigaction(SIGPIPE, &sa, NULL);
}

static void install_seccomp_guard(void) __attribute__((constructor(101)));
static void install_seccomp_guard(void) {
  memset(g_fake_obj, 0, sizeof(g_fake_obj));
  /* Seed fake vtable-ish pointers so loads of [obj+0] are non-null. */
  for (size_t i = 0; i + sizeof(uintptr_t) <= sizeof(g_fake_obj); i += sizeof(uintptr_t)) {
    uintptr_t self = (uintptr_t)(g_fake_obj + i);
    memcpy(g_fake_obj + i, &self, sizeof(self));
  }

  install_early_signal_ignores();

  pthread_t th;
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  if (pthread_create(&th, &attr, deferred_guard_thread, NULL) != 0) {
    /* Fallback: install immediately rather than never. */
    install_crash_guards_now();
  }
  pthread_attr_destroy(&attr);

  struct sock_filter filter[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
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

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    return;
  }
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
#ifdef __NR_seccomp
    syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
            1 /* SECCOMP_FILTER_FLAG_TSYNC */, &prog);
#endif
  }
}

int kill(pid_t pid, int sig) {
  (void)pid;
  (void)sig;
  ensure_crash_guards();
  return 0;
}

int tgkill(int tgid, int tid, int sig) {
  (void)tgid;
  (void)tid;
  (void)sig;
  ensure_crash_guards();
  return 0;
}

int tkill(int tid, int sig) {
  (void)tid;
  (void)sig;
  ensure_crash_guards();
  return 0;
}

int pthread_kill(pthread_t thread, int sig) {
  (void)thread;
  (void)sig;
  ensure_crash_guards();
  return 0;
}

int raise(int sig) {
  /* Allow crash_guard to re-raise unfixable faults to the default handler. */
  if (g_in_fatal_raise) {
    typedef int (*real_raise_t)(int);
    static real_raise_t real_raise;
    if (!real_raise) {
      real_raise = (real_raise_t)dlsym(RTLD_NEXT, "raise");
    }
    if (real_raise) {
      return real_raise(sig);
    }
  }
  (void)sig;
  ensure_crash_guards();
  return 0;
}

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
    ensure_crash_guards();
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
