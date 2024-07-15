/*
 * simplevpn.h - Provide simplevpn client service
 *
 * Copyright (C) 2018, hxdyxd <hxdyxd@gmail.com>
 *
 * This file is part of the simplevpn.
 *
 * simplevpn is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * simplevpn is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with simplevpn; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */
#ifndef _SIMPLEVPN_H_
#define _SIMPLEVPN_H_

#include <stdint.h>
#include <sys/socket.h>
#include <net/if.h>

#define DEFAULT_PASSWORD      ""
#define MODE_SWITCH      0
#define MODE_CLIENT      1
#define MAX_SERVER_NUM   10
#define MAX_LOCAL_NUM    1
#define MAX_TAP_NUM      1
#define MAX_CTX_NUM      (MAX_SERVER_NUM + MAX_LOCAL_NUM + MAX_TAP_NUM)

enum switch_type {
    SWITCH_NONE = 0,
    SWITCH_UDP,
    SWITCH_TAP,
};

enum cmd_type {
    SWITCH_CMD_NONE,
    SWITCH_CMD_START,
    SWITCH_CMD_STOP,
    SWITCH_CMD_RESTART,
};

struct switch_ctx_t {
    enum switch_type type;
    union {
        struct {
            int sock;
            int if_bind;
            int if_local;
            struct sockaddr_storage localaddr;
            struct sockaddr_storage addr;
        }udp;
        struct {
            int fd;
            char ifname[IFNAMSIZ];
        }tap;
    };
};

struct switch_addr_t {
    char host[128];
    char port[32];
};

struct switch_args_t {
    enum cmd_type cmd;
    struct switch_addr_t local_addr;
    struct switch_addr_t server_addr[MAX_SERVER_NUM];
    int if_bind;
    int server_count;
    int ipv6;
    int has_tap;
    const char *pid_file;
    const char *log_file;
    const char *password;
    uint16_t mtu;
};


int switch_run(struct switch_args_t *args);

#endif
