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

#define CACHE_TIME_OUT   (600 * 1000)
#define HWADDR_LEN       (6)

struct cache_table_t {
    uint32_t time;
    int forever;
    uint8_t hwaddr[HWADDR_LEN];
    uint32_t tx_bytes;
    uint32_t rx_bytes;
    uint32_t tx_pks;
    uint32_t rx_pks;
    struct switch_ctx_t ctx;
    UT_hash_handle hh;          /* makes this structure hashable */
    UT_hash_handle hh_tmp;
};

void cache_table_add(struct cache_table_t **table, void *hwaddr, uint32_t time, struct switch_ctx_t *pctx);
void cache_table_add_heart(struct cache_table_t **table, uint32_t time, struct switch_ctx_t *pctx);
void cache_table_add_forever(struct cache_table_t **table, int forever, struct switch_ctx_t *pctx);
struct cache_table_t *cache_table_find(struct cache_table_t **table, void *hwaddr);
void cache_table_delete(struct cache_table_t **table, void *hwaddr);
void cache_table_delete_all(struct cache_table_t **table);
int cache_table_count(struct cache_table_t **table);
void cache_table_print(struct cache_table_t **table);
void cache_table_iter_once(struct cache_table_t **table,
                            void (*call_user_fun)(struct cache_table_t *, void *p),
                            void *p
);
int switch_dump_send_route(struct switch_ctx_t *psctx, struct cache_table_t *s, char *msg);

#endif
