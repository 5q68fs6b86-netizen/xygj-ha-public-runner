/*
 * Ephemeral CI LD_PRELOAD for the re-signed x86 shell.
 *
 * 1) Neutralize self-kill helpers so anti-tamper cannot SIGKILL the process.
 * 2) Neutralize setuid/setgid family calls: wrap.<pkg> re-enters Zygote via
 *    WrapperInit, which forks and calls setgid during AssetManager idmap
 *    verification. App seccomp blocks those syscalls (SIGSYS / syscall 106).
 *    Returning success without the syscall lets preload finish.
 *
 * Built on the Actions runner with the Android NDK; never ships to users.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <grp.h>

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
