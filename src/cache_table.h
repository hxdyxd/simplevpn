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

#define HWADDR_LEN   (6)

struct cache_table_t {
	uint8_t hwaddr[HWADDR_LEN];
	uint64_t time;
	struct sockaddr_storage addr;
	UT_hash_handle hh;         /* makes this structure hashable */
	UT_hash_handle hh_tmp;
};

void cache_table_add(struct cache_table_t **table, void *hwaddr, uint64_t time, void *addr);
struct cache_table_t *cache_table_find(struct cache_table_t **table, void *hwaddr);
void cache_table_delete(struct cache_table_t **table, void *hwaddr);
void cache_table_delete_all(struct cache_table_t **table);
int cache_table_count(struct cache_table_t **table);
void cache_table_print(struct cache_table_t **table);
void cache_table_iter_once(struct cache_table_t **table,
						   void (*call_user_fun)(struct cache_table_t *, void *p),
						   void *p
);

#endif
