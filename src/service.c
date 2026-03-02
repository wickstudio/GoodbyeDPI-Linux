/*
 * Linux Daemon Service for GoodbyeDPI-Linux
 *
 * Replaces Windows Service Manager with POSIX daemonization.
 * Provides PID file management and signal handling.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include "service.h"

#define DEFAULT_PIDFILE "/var/run/goodbyedpi.pid"

/**
 * Daemonize the process
 * Standard POSIX double-fork technique
 */
int service_daemonize(void) {
    pid_t pid;

    /* First fork */
    pid = fork();
    if (pid < 0) {
        perror("service_daemonize: fork");
        return -1;
    }
    if (pid > 0) {
        /* Parent exits */
        exit(EXIT_SUCCESS);
    }

    /* Create new session */
    if (setsid() < 0) {
        perror("service_daemonize: setsid");
        return -1;
    }

    /* Ignore signals */
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    /* Second fork */
    pid = fork();
    if (pid < 0) {
        perror("service_daemonize: fork");
        return -1;
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    /* Set file permissions */
    umask(0);

    /* Change to root directory */
    if (chdir("/") < 0) {
        perror("service_daemonize: chdir");
        return -1;
    }

    /* Close standard file descriptors and redirect to /dev/null */
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        if (devnull > 2)
            close(devnull);
    }

    return 0;
}

/**
 * Write PID file
 */
int service_write_pidfile(const char *pidfile) {
    const char *path = pidfile ? pidfile : DEFAULT_PIDFILE;
    FILE *fp = fopen(path, "w");
    if (!fp) {
        perror("service_write_pidfile");
        return -1;
    }
    fprintf(fp, "%d\n", getpid());
    fclose(fp);
    return 0;
}

/**
 * Remove PID file
 */
void service_remove_pidfile(const char *pidfile) {
    const char *path = pidfile ? pidfile : DEFAULT_PIDFILE;
    unlink(path);
}
