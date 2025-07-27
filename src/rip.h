/*
 * rip.h - Provide simplevpn switch service
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

#ifndef _RIP_H_
#define _RIP_H_

#include <stdint.h>
#include <netinet/in.h>
#include "simplevpn.h"

//rip
int send_to_self(UDP_CTX *ctx_p);
int switch_send_heart(UDP_CTX *ctx, void *buff1, void *buff2, int len, struct switch_main_t *psmb);
int switch_process_heart(UDP_CTX *ctx, void *buff1, void *buff2, int len, struct switch_main_t *psmb);

#endif
