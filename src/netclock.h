/*
 * netclock.h  - Provide simplevpn switch service
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
#ifndef _NETCLOCK_H_
#define _NETCLOCK_H_

#include <time.h>
#include <sys/time.h>

static inline uint32_t get_time_ms(void)
{
    int r;

#ifdef NO_CLOCK_MONOTONIC
    struct timeval tv;

    r = gettimeofday(&tv, NULL);
    if (r < 0) {
        ERROR_PRINTF("gettimeofday() %s\n", strerror(errno));
        return 0;
    }
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
#else
    struct timespec tv;

    r = clock_gettime(
#ifdef CLOCK_MONOTONIC_RAW
        CLOCK_MONOTONIC_RAW,
#else
        CLOCK_MONOTONIC,
#endif
        &tv);
    if (r < 0) {
        return 0;
    }
    return tv.tv_sec * 1000 + tv.tv_nsec / 1000 / 1000;
#endif
}

#endif
