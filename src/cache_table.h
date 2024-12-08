/*
 * cache_table.h - Provide simplevpn switch service
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

#ifndef _CACHE_TABLE_H_
#define _CACHE_TABLE_H_

#include <stdint.h>
#include <netinet/in.h>
#include "uthash.h"
#include "simplevpn.h"

#define CACHE_TIME_OUT           (600 * 1000)
#define CACHE_ROUTE_TIME_OUT     (60 * 1000)
#define CACHE_ROUTE_GC_OUT       (40 * 1000)
#define CACHE_ROUTE_METRIC_MAX   (16)
#define CACHE_ROUTE_UPDATE_TIME  (10 * 1000)
#define HWADDR_LEN            (6)

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

#define cache_router_iter(rt,s,tmp) HASH_ITER(hh, *(rt)->table, s, tmp)

void cache_router_add(struct cache_router_t *rt);
struct cache_router_t *cache_router_find(struct cache_router_t *rt, uint32_t dest_router);
struct cache_router_t *cache_router_search(struct cache_router_t *rt, uint32_t dest_router);
struct cache_router_t *cache_router_find_by_addr(struct cache_router_t *rt, struct sockaddr_storage *addr);
void cache_route_printall(struct cache_router_t *rt);
int cache_router_count(struct cache_router_t *rt);
void cache_router_delete_all(struct cache_router_t *rt);
void cache_route_iter(struct cache_router_t *rt,
                           void (*call_user_fun)(const struct cache_router_t *, struct cache_router_t *, void *p),
                           void *p);

int switch_dump_send_router(struct switch_ctx_t *psctx, struct cache_router_t *s, char *msg);

#endif
