/**
  daemon.c

  Copyright (C) 2015 clowwindy

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include "simplevpn.h"
#include "app_debug.h"

#define PID_BUF_SIZE 32

static int write_pid_file(const char *filename, pid_t pid);

static void sig_handler_exit(int signo)
{
    exit(0);
}

int daemon_start(const struct switch_args_t *args)
{
    pid_t pid = fork();
    if (pid == -1) {
        APP_ERROR("fork\n");
        return -1;
    }
    if (pid > 0) {
        // let the child print message to the console first
        signal(SIGINT, sig_handler_exit);
        sleep(5);
        exit(0);
    } 

    pid_t ppid = getppid();
    pid = getpid();
    if (0 != write_pid_file(args->pid_file, pid)) {
        kill(ppid, SIGINT);
        return -1;
    }

    setsid();
    signal(SIGHUP, SIG_IGN);

    // print on console
    APP_INFO("started\n");
    kill(ppid, SIGINT);

    // then rediret stdout & stderr
    fclose(stdin);
    FILE *fp;
    fp = freopen(args->log_file, "a", stdout);
    if (fp == NULL) {
        APP_ERROR("freopen\n");
        return -1;
    }
    fp = freopen(args->log_file, "a", stderr);
    if (fp == NULL) {
        APP_ERROR("freopen\n");
        return -1;
    }

    return 0;
}

static int write_pid_file(const char *filename, pid_t pid)
{
    char buf[PID_BUF_SIZE];
    int fd = open(filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        APP_ERROR("can not open %s\n", filename);
        APP_ERROR("open\n");
        return -1;
    }
    int flags = fcntl(fd, F_GETFD);
    if (flags == -1) {
        APP_ERROR("fcntl\n");
        return -1;
    }

    flags |= FD_CLOEXEC;
    if (-1 == fcntl(fd, F_SETFD, flags))
        APP_ERROR("fcntl\n");

    struct flock fl;
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    if (-1 == fcntl(fd, F_SETLK, &fl)) {
        ssize_t n = read(fd, buf, PID_BUF_SIZE - 1);
        if (n > 0) {
            buf[n] = 0;
            APP_ERROR("already started at pid %ld\n", atol(buf));
        } else {
            APP_ERROR("already started\n");
        }
        close(fd);
        return -1;
    }
    if (-1 == ftruncate(fd, 0)) {
        APP_ERROR("ftruncate\n");
        return -1;
    }
    snprintf(buf, PID_BUF_SIZE, "%ld\n", (long)getpid());

    if (write(fd, buf, strlen(buf)) != strlen(buf)) {
        APP_ERROR("write\n");
        return -1;
    }
    return 0;
}

int daemon_stop(const struct switch_args_t *args)
{
    char buf[PID_BUF_SIZE];
    int i, stopped;
    FILE *fp = fopen(args->pid_file, "r");
    if (fp == NULL) {
        APP_ERROR("not running\n");
        return 0;
    }
    char *line = fgets(buf, PID_BUF_SIZE, fp);
    fclose(fp);
    if (line == NULL) {
        APP_ERROR("fgets\n");
        return 0;
    }
    pid_t pid = (pid_t)atol(buf);
    if (pid > 0) {
        // make sure pid is not zero or negative
        if (0 != kill(pid, SIGTERM)){
            if (errno == ESRCH) {
                APP_ERROR("not running\n");
                return 0;
            }
        APP_ERROR("kill\n");
        return -1;
        }
        stopped = 0;
        // wait for maximum 10s
        for (i = 0; i < 200; i++) {
            if (-1 == kill(pid, 0)) {
                if (errno == ESRCH) {
                    stopped = 1;
                    break;
                }
            }
            // sleep 0.05s
            usleep(50000);
        }
        if (!stopped) {
            APP_ERROR("timed out when stopping pid %d\n", pid);
            return -1;
        }
        APP_ERROR("stopped\n");
        if (0 != unlink(args->pid_file)) {
            APP_ERROR("unlink\n");
            return -1;
        }
    } else {
        APP_ERROR("pid is not positive: %ld\n", (long)pid);
        return -1;
    }
    return 0;
}

