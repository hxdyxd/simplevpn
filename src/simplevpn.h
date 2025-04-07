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
#include "list.h"
#include "uthash.h"

#define DEFAULT_PASSWORD      ""
#define MODE_SWITCH      0
#define MODE_CLIENT      1
#define MAX_SERVER_NUM   10
#define MAX_LOCAL_NUM    10
#define MAX_TAP_NUM      1
#define MAX_CTX_NUM      (MAX_SERVER_NUM + MAX_LOCAL_NUM + MAX_TAP_NUM)
#define DEFAULT_METRIC   100
#define MAX_PREFIX_NUM   10

#define TCP_KEEPALIVE_TIME     60
#define TCP_KEEPALIVE_INTVL    10
#define TCP_KEEPALIVE_CNT      3

#define SWITCH_IFNAMSIZ 16

#define SWITCH_POLLIN   0x0001
#define SWITCH_POLLOUT  0x0004
#define SWITCH_POLLERR  0x0008

enum switch_type {
    SWITCH_NONE = 0,
    SWITCH_UDP,
    SWITCH_TCP,
    SWITCH_TAP,
};

enum cmd_type {
    SWITCH_CMD_NONE,
    SWITCH_CMD_START,
    SWITCH_CMD_STOP,
    SWITCH_CMD_RESTART,
};

struct switch_addr_t {
    char host[128];
    char port[32];
    int if_tcp;
};

struct switch_prefix_t {
    char prefix[128];
    uint32_t len;
};

struct switch_ctx_t {
    uint32_t router_mac;
    enum switch_type type;
    struct list_head list;
    uint64_t counter;
    uint32_t msg_time;
    uint32_t events;
    union {
        int sock;
        struct {
            int sock;
            int if_bind;
            int if_local;
            struct sockaddr_storage localaddr;
            struct sockaddr_storage addr;
        }udp;
        struct {
            int sock;
            int if_bind;
            int if_local;
            struct sockaddr_storage localaddr;
            struct sockaddr_storage addr;
            struct switch_addr_t local_addr;
            uint8_t *write_buffer;
            int write_buffer_size;
            int write_pos;
            int write_size;
            uint8_t *read_buffer;
            int read_buffer_size;
            int read_pos;
            int read_size;
        }tcp;
        struct {
            int fd;
            int if_native;
            char ifname[SWITCH_IFNAMSIZ];
        }tap;
    };
};

struct cache_router_t {
    uint32_t router_mac;
    uint32_t dest_router;
    uint32_t next_hop_router;
    uint32_t time;
    uint8_t prefix_length;
    uint8_t metric;
    uint32_t tx_bytes;
    uint32_t rx_bytes;
    uint32_t tx_pks;
    uint32_t rx_pks;
    uint32_t rtt_time;
    uint32_t rtt_send_time;
    uint32_t gc_time;
    uint32_t gc_enable;
    uint8_t alloced_ctx;
    int (*add_router)(struct cache_router_t *, int);
    void *router_data;
    struct switch_ctx_t *ctx;
    UT_hash_handle hh;
    struct cache_router_t **table;
};

struct switch_main_t {
    struct switch_ctx_t   head;
    struct cache_router_t param;
    uint32_t current_time;
};

struct switch_args_t {
    enum cmd_type cmd;
    char local_network[128];
    char default_network[128];
    int if_local_network;
    int if_default_network;
    struct switch_addr_t local_addr[MAX_LOCAL_NUM];
    struct switch_addr_t server_addr[MAX_SERVER_NUM];
    struct switch_prefix_t prefixs[MAX_PREFIX_NUM];
    int local_count;
    int server_count;
    int prefix_count;
    int ipv6;
    int has_tap;
    int tun_fd;
    const char *pid_file;
    const char *log_file;
    const char *password;
    uint16_t mtu;
    int running;
};


int switch_run(struct switch_args_t *args);
int switch_reconnect_tcp(struct switch_ctx_t *ctx);
struct switch_ctx_t *switch_add_accepted_tcp(struct switch_main_t *smb, struct switch_ctx_t *ctx);
struct switch_ctx_t *switch_add_tcp(struct switch_main_t *smb, int if_bind, const char *host, const char *port);
struct switch_ctx_t *switch_add_udp(struct switch_main_t *smb, int if_bind, const char *host, const char *port);
struct switch_ctx_t *switch_add_tap(struct switch_main_t *smb, int flags, uint16_t mtu);

//switch
int switch_read_encode(uint8_t *out, uint8_t *in, int rlen);
int switch_address_cmp(struct switch_ctx_t *ctxa, struct switch_ctx_t *ctxb);

//rip
typedef struct {
    void *cbuf;
    void *pbuf;
    int clen;
    int plen;
    char type;
    uint32_t saddr;
    uint32_t daddr;
    uint32_t default_addr;
    struct switch_ctx_t *src_pctx;
} UDP_CTX;

//utils
void msg_dump(void *buf, int len);
uint16_t switch_in_cksum(const uint16_t *buf, int bufsz);



#endif
