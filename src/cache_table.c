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
#include "netclock.h"
#include "udp_alloc.h"
#include "app_debug.h"
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

static int switch_dump_ctx__(struct switch_ctx_t *psctx, char *msg, void *buff, int len)
{
    char *ip = "";
    uint16_t port = 0;
    char addr_buf[INET6_ADDRSTRLEN];
    if (SWITCH_TAP == psctx->type) {
        return snprintf(buff, len, "%s !type=%d fd=%d ifname=%s",
         msg, psctx->type,
         psctx->tap.fd, psctx->tap.ifname);
    }

    if (SWITCH_UDP == psctx->type) {
        vpn_udp_ntop(&psctx->udp.addr, addr_buf, sizeof(addr_buf), &ip, &port);

        return snprintf(buff, len, "%s |type=%d fd=%d peer=%s:%u",
         msg, psctx->type,
         psctx->udp.sock, ip, port);
    }
    return -1;
}

static int switch_dump_table__(struct cache_table_t *s, char *msg, void *buff, int len)
{
    struct switch_ctx_t *psctx = &s->ctx;
    char *ip = "";
    uint16_t port = 0;
    char addr_buf[INET6_ADDRSTRLEN];
    if (SWITCH_TAP == psctx->type) {
        return snprintf(buff, len, "%s !hw=%02x:%02x:%02x:%02x:%02x:%02x fd=%d ifname=%s",
         msg,
         s->hwaddr[0],s->hwaddr[1],s->hwaddr[2],s->hwaddr[3],s->hwaddr[4],s->hwaddr[5],
         s->ctx.tap.fd, s->ctx.tap.ifname);
    }

    if (SWITCH_UDP == psctx->type) {
        vpn_udp_ntop(&psctx->udp.addr, addr_buf, sizeof(addr_buf), &ip, &port);

        return snprintf(buff, len, "%s |hw=%02x:%02x:%02x:%02x:%02x:%02x fd=%d peer=%s:%u",
         msg,
         s->hwaddr[0],s->hwaddr[1],s->hwaddr[2],s->hwaddr[3],s->hwaddr[4],s->hwaddr[5],
         s->ctx.udp.sock, ip, port);
    }
    return -1;
}

int switch_dump_send_route(struct switch_ctx_t *psctx, struct cache_table_t *s, char *msg)
{
    int ret = -1;
    char sbuff[128];
    char tbuff[128];

    memset(sbuff, 0, sizeof(sbuff));
    memset(tbuff, 0, sizeof(sbuff));

    if (psctx) {
        ret = switch_dump_ctx__(psctx, "from", sbuff, sizeof(sbuff));
        if (ret < 0)
            return ret;
    }
    ret = switch_dump_table__(s, "to", tbuff, sizeof(tbuff));
    if (ret < 0)
        return ret;

    APP_DEBUG("%s %s -> %s\n", msg, sbuff, tbuff);
    return 0;
}

void cache_table_add(struct cache_table_t **table, void *hwaddr, uint32_t time, struct switch_ctx_t *pctx)
{
    int add = 0;
    struct cache_table_t *s;
    if(table == NULL || hwaddr == NULL || pctx == NULL) {
        return;
    }
    HASH_FIND( hh, *table, hwaddr, HWADDR_LEN, s);  /* id already in the hash? */
    if (s==NULL) {
        s = (struct cache_table_t *)calloc(1, sizeof *s);
        memcpy(s->hwaddr, hwaddr, HWADDR_LEN);
        HASH_ADD_KEYPTR( hh, *table, s->hwaddr, HWADDR_LEN, s);
        add = 1;
    }
    s->time = time;
    s->forever = 0;
    memcpy(&s->ctx, pctx, sizeof(struct switch_ctx_t));
    if (add) {
        switch_dump_send_route(NULL, s, "[add]");
    } else {
        if (s->ctx.type != pctx->type) {
            switch_dump_send_route(NULL, s, "[update type]");
        } else if (SWITCH_UDP == pctx->type) {
            if (memcmp(&s->ctx.udp.addr, &pctx->udp.addr, sizeof(struct sockaddr_storage)) != 0) {
                switch_dump_send_route(NULL, s, "[update address]");
            }
        } else if (SWITCH_TAP == pctx->type) {
            if (s->ctx.tap.fd != pctx->tap.fd) {
                switch_dump_send_route(NULL, s, "[update tap]");
            }
        }
    }
}

void cache_table_add_heart(struct cache_table_t **table, uint32_t time, struct switch_ctx_t *pctx)
{
    struct cache_table_t *s;
    if(table == NULL || SWITCH_UDP != pctx->type || pctx == NULL) {
        return;
    }
    HASH_FIND( hh, *table, &pctx->udp.addr, sizeof(struct sockaddr_storage), s);  /* id already in the hash? */
    if (s==NULL) {
        s = (struct cache_table_t *)calloc(1, sizeof *s);
        memcpy(&s->ctx.udp.addr, &pctx->udp.addr, sizeof(struct sockaddr_storage));
        HASH_ADD_KEYPTR( hh, *table, &s->ctx.udp.addr, sizeof(struct sockaddr_storage), s);
    }
    s->time = time;
    s->forever = 0;
    memset(s->hwaddr, 0xff, HWADDR_LEN);
    memcpy(&s->ctx, pctx, sizeof(struct switch_ctx_t));
}

void cache_table_add_forever(struct cache_table_t **table, int forever, struct switch_ctx_t *pctx)
{
    struct cache_table_t *s;
    if(table == NULL || pctx == NULL) {
        return;
    }
    HASH_FIND_INT(*table, &forever, s);  /* id already in the hash? */
    if (s==NULL) {
        s = (struct cache_table_t *)calloc(1, sizeof *s);
        s->forever = forever;
        HASH_ADD_INT(*table, forever, s);
    }
    s->time = 0;
    memset(s->hwaddr, 0xff, HWADDR_LEN);
    memcpy(&s->ctx, pctx, sizeof(struct switch_ctx_t));
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
    uint32_t cache_time = 0;
    char addr_buf[INET6_ADDRSTRLEN];
    if(table == NULL) {
        return;
    }
    cache_time = get_time_ms();

    HASH_ITER(hh, *table, s, tmp) {
        uint32_t time_dif = cache_time - s->time;
        if (s->forever) {
            time_dif = 0;
        } else if(time_dif > CACHE_TIME_OUT) {
            switch_dump_send_route(NULL, s, "[del]");
            HASH_DEL( *table, s);  /* user: pointer to deletee */
            free(s);             /* optional; it's up to you! */
            continue;
        }

        char *ip = "";
        uint16_t port = 0;
        if (SWITCH_TAP == s->ctx.type) {
            APP_INFO("!hw=%02x:%02x:%02x:%02x:%02x:%02x fd=%d ifname=%s time=%u tx=%u %s\n",
             s->hwaddr[0],s->hwaddr[1],s->hwaddr[2],s->hwaddr[3],s->hwaddr[4],s->hwaddr[5],
             s->ctx.tap.fd, s->ctx.tap.ifname, time_dif,
             s->tx_bytes, s->forever ? "forever": "");
        }

        if (SWITCH_UDP == s->ctx.type) {
            vpn_udp_ntop(&s->ctx.udp.addr, addr_buf, sizeof(addr_buf), &ip, &port);

            APP_INFO("|hw=%02x:%02x:%02x:%02x:%02x:%02x fd=%d bind=%d local=%d peer=%s:%u time=%u tx=%u %s\n",
             s->hwaddr[0],s->hwaddr[1],s->hwaddr[2],s->hwaddr[3],s->hwaddr[4],s->hwaddr[5],
             s->ctx.udp.sock, s->ctx.udp.if_bind, s->ctx.udp.if_local, ip, port, time_dif,
             s->tx_bytes, s->forever ? "forever": "");
        }
    }
}

/* ipv6 & ipv4 todo... */
static int cache_table_addr_add(struct cache_table_t **table, struct cache_table_t *t)
{
    struct cache_table_t *s;
    if (table == NULL || t == NULL) {
        return -1;
    }
    HASH_FIND( hh_tmp, *table, &t->ctx.udp.addr, sizeof(struct sockaddr_storage), s);  /* id already in the hash? */
    if (s==NULL) {
        s = t;
        HASH_ADD_KEYPTR( hh_tmp, *table, &s->ctx.udp.addr, sizeof(struct sockaddr_storage), s);
        return 0;
    } else {
        return 1;
    }
}

static int cache_table_addr_tapfd(struct cache_table_t **table, struct cache_table_t *t)
{
    struct cache_table_t *s;
    if (table == NULL || t == NULL) {
        return -1;
    }
    HASH_FIND( hh_tmp, *table, &t->ctx.tap.fd, sizeof(t->ctx.tap.fd), s);  /* id already in the hash? */
    if (s==NULL) {
        s = t;
        HASH_ADD_KEYPTR( hh_tmp, *table, &s->ctx.tap.fd, sizeof(t->ctx.tap.fd), s);
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
        if (SWITCH_TAP == s->ctx.type) {
            int r = cache_table_addr_tapfd(&table_addr, s);
            if(r == 1 || r < 0) {
                continue;
            }
        } else if (SWITCH_UDP == s->ctx.type) {
            int r = cache_table_addr_add(&table_addr, s);
            if(r == 1 || r < 0) {
                continue;
            }
        }
        //printf("hwaddr:%02x:%02x:%02x:%02x:%02x:%02x time:%u count:%d\n",
        // s->hwaddr[0],s->hwaddr[1],s->hwaddr[2],s->hwaddr[3],s->hwaddr[4],s->hwaddr[5],
        // s->time,
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
        printf("find hwaddr:%02x:%02x:%02x:%02x:%02x:%02x time:%u \n",
         s->hwaddr[0],s->hwaddr[1],s->hwaddr[2],s->hwaddr[3],s->hwaddr[4],s->hwaddr[5],
         s->time);
    }
    
    cache_table_delete(&t, "\0\0\0\0\0\2");
    cache_table_delete_all(&t);
        
    cache_table_print(&t);
    return 0;
}
#endif
