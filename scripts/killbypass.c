/*
 * Ephemeral CI LD_PRELOAD for the re-signed x86 shell.
 * Neutralize self-termination kill paths so DarkDex can observe a living
 * process long enough to carve decrypted DEX images.
 *
 * Built on the Actions runner with the Android NDK; never ships to users.
 * Intentionally narrow: only signal-delivery helpers, not exit/abort, so
 * normal ART teardown is not frozen into an infinite pause.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

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
