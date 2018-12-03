/*
 * cache_table.c - Provide simplevpn switch service
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

#include "cache_table.h"
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>

#define TEST         (0)

#if TEST
struct sockaddr_storage {
	char name[5];
};
#endif

void cache_table_add(struct cache_table_t **table, void *hwaddr, uint64_t time, void *addr)
{
	struct cache_table_t *s;
	if(table == NULL || hwaddr == NULL || addr == NULL) {
		return;
	}
	HASH_FIND( hh, *table, hwaddr, HWADDR_LEN, s);  /* id already in the hash? */
	if (s==NULL) {
		s = (struct cache_table_t *)malloc(sizeof *s);
		memcpy(s->hwaddr, hwaddr, HWADDR_LEN);
		HASH_ADD_KEYPTR( hh, *table, s->hwaddr, HWADDR_LEN, s);
	}
	s->time = time;
	memcpy(&s->addr, addr, sizeof(struct sockaddr_storage));
}

struct cache_table_t *cache_table_find(struct cache_table_t **table, void *hwaddr)
{
	struct cache_table_t *s;
	if(table == NULL || hwaddr == NULL) {
		return NULL;
	}
	HASH_FIND( hh, *table, hwaddr, HWADDR_LEN, s);  /* s: output pointer */
	return s;
}

void cache_table_delete(struct cache_table_t **table, void *hwaddr)
{
	struct cache_table_t *s;
	if(table == NULL || hwaddr == NULL) {
		return;
	}
	HASH_FIND( hh, *table, hwaddr, HWADDR_LEN, s);
	if(s != NULL) {
		HASH_DEL( *table, s);  /* user: pointer to deletee */
		free(s);             /* optional; it's up to you! */
	}
}

void cache_table_delete_all(struct cache_table_t **table)
{
	struct cache_table_t *current_table, *tmp;
	if(table == NULL) {
		return;
	}
	HASH_ITER(hh, *table, current_table, tmp) {
		HASH_DEL( *table, current_table);  /* delete; users advances to next */
		free(current_table);            /* optional- if you want to free  */
	}
}

int cache_table_count(struct cache_table_t **table)
{
	if(table == NULL) {
		return 0;
	}
    return HASH_COUNT(*table);
}

void cache_table_print(struct cache_table_t **table)
{
    struct cache_table_t *s, *tmp;
    struct timeval cache_tv;
    uint8_t addr_buf[100];
    if(table == NULL) {
		return;
	}
	if(gettimeofday(&cache_tv, NULL) < 0) {
        cache_tv.tv_sec = 0;
    }
    HASH_ITER(hh, *table, s, tmp) {
    	uint64_t time_dif = cache_tv.tv_sec - s->time;
    	if(time_dif > CACHE_TIME_OUT) {
    		HASH_DEL( *table, s);  /* user: pointer to deletee */
			free(s);             /* optional; it's up to you! */
    		continue;
    	}
		socklen_t sin_size;
		const char *ip;
		uint16_t port;
		if(s->addr.ss_family == AF_INET) {
		    sin_size = sizeof(struct sockaddr_in);
		    struct sockaddr_in *addr_v4 = (struct sockaddr_in *)&s->addr;
		    port = ntohs(addr_v4->sin_port);
		    ip = inet_ntop(s->addr.ss_family, &addr_v4->sin_addr, addr_buf, sin_size);
		} else if(s->addr.ss_family == AF_INET6) {
		    sin_size = sizeof(struct sockaddr_in6);
		    struct sockaddr_in6 *addr_v6 = (struct sockaddr_in6 *)&s->addr;
		    port = ntohs(addr_v6->sin6_port);
		    ip = inet_ntop(s->addr.ss_family, &addr_v6->sin6_addr, addr_buf, sin_size);
		} else {
		    printf("Unknown AF\n");
		    continue;
		}

        printf("|addr=%s:%d\t hw=%02x:%02x:%02x:%02x:%02x:%02x\t time=%lld\n",
         ip, port,
		 s->hwaddr[0],s->hwaddr[1],s->hwaddr[2],s->hwaddr[3],s->hwaddr[4],s->hwaddr[5],
		 (long long int)time_dif );
    }
}

static int cache_table_addr_add(struct cache_table_t **table, struct cache_table_t *t)
{
	struct cache_table_t *s;
	if(table == NULL || t == NULL) {
		return -1;
	}
	HASH_FIND( hh_tmp, *table, &t->addr, sizeof(struct sockaddr_storage), s);  /* id already in the hash? */
	if (s==NULL) {
		s = t;
		HASH_ADD_KEYPTR( hh_tmp, *table, &s->addr, sizeof(struct sockaddr_storage), s);
		return 0;
	} else {
		return 1;
	}
}

static void cache_table_addr_delete_all(struct cache_table_t **table)
{
	struct cache_table_t *current_table, *tmp;
	if(table == NULL) {
		return;
	}
	HASH_ITER(hh_tmp, *table, current_table, tmp) {
		HASH_DELETE(hh_tmp, *table, current_table);  /* delete; users advances to next */
	}
}

void cache_table_iter_once(struct cache_table_t **table,
						   void (*call_user_fun)(struct cache_table_t *, void *p),
						   void *p)
{
    struct cache_table_t *s, *tmp;
    struct cache_table_t *table_addr = NULL;
    if(table == NULL) {
		return;
	}
    HASH_ITER(hh, *table, s, tmp) {
    	int r = cache_table_addr_add(&table_addr, s);
    	if(r == 1 || r < 0) {
    		continue;
    	}
        //printf("hwaddr:%02x:%02x:%02x:%02x:%02x:%02x time:%lld count:%d\n",
		// s->hwaddr[0],s->hwaddr[1],s->hwaddr[2],s->hwaddr[3],s->hwaddr[4],s->hwaddr[5],
		// (long long int)s->time,
		// cache_table_count(table) );
        call_user_fun(s, p);
    }
    cache_table_addr_delete_all(&table_addr);
}

#if TEST
int main()
{
	struct cache_table_t *t = NULL;
	struct sockaddr_storage addr = {
		"123",
	};
	
	cache_table_add(&t, "123456", 12, &addr);
	cache_table_add(&t, "123456", 12, &addr);
	cache_table_add(&t, "\0\0\0\0\0\2", 22, &addr);
	
	struct cache_table_t *s = cache_table_find(&t, "\0\0\0\0\0\2");
	if(s == NULL) {
		printf("not found\n");
	} else {
		printf("find hwaddr:%02x:%02x:%02x:%02x:%02x:%02x time:%lld \n",
		 s->hwaddr[0],s->hwaddr[1],s->hwaddr[2],s->hwaddr[3],s->hwaddr[4],s->hwaddr[5],
		 s->time);
	}
	
	cache_table_delete(&t, "\0\0\0\0\0\2");
	cache_table_delete_all(&t);
		
	cache_table_print(&t);
	return 0;
}
#endif
