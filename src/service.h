/* Linux daemon management functions for GoodbyeDPI-Linux */

/* Daemonize the process (fork, setsid, close fds) */
int service_daemonize(void);

/* Write PID file */
int service_write_pidfile(const char *pidfile);

/* Remove PID file */
void service_remove_pidfile(const char *pidfile);
