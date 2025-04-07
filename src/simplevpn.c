/*
 * simplevpn.c - Provide simplevpn client service
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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "app_debug.h"
#include "daemon.h"
#include "simplevpn.h"
#include "crypto.h"

#define VERSION "0.1.2"
#define DEBUG_INFO     1
#define TIME_DEBUG    15

#define DEFAULT_LOCAL_HOST   "127.0.0.1"
#define DEFAULT_LOCAL_PORT        "2020"


void usage(void)
{
    PRINTF("\n");
    PRINTF("simplevpn %s\n\n", VERSION);
    PRINTF("  usage:\n\n");
    PRINTF("    simplevpn\n");
    PRINTF("\n");
    PRINTF(
        "       -l <local_addr>            Your local udp address.\n");
    PRINTF(
        "       -r <remote_addr>           Your remote server udp address.\n");
    PRINTF(
        "       -L <local_addr>            Your local tcp address.\n");
    PRINTF(
        "       -R <remote_addr>           Your remote server tcp address.\n");
    PRINTF(
        "       [-t]                       Create tap device.\n");
    PRINTF(
        "       -k <password>              Password of your remote server.\n");
    PRINTF(
        "       -n <local_network>         Local network.\n");
    PRINTF(
        "       -g <default_network>       Default network.\n");
    PRINTF(
        "       -p <prefix>                Your network prefixs address.\n");
    PRINTF(
        "       -d <cmd>                   Daemon start/stop/restart\n");
    PRINTF(
        "       -s <block_size>            Crypto speed test\n");
    PRINTF(
        "       -e <log level>             0:never    1:fatal   2:error   3:warn\n");
    PRINTF(
        "                                  4:info (default)     5:debug   6:trace\n");
    PRINTF("\n");
    PRINTF(
        "       [-v]                       Verbose mode.\n");
    PRINTF(
        "       [-h, --help]               Print this message.\n");
    PRINTF("\n");
}

int args_parse(struct switch_args_t *args, int argc, char **argv)
{
    int ch;
    int block_size = 0;

    memset(args, 0, sizeof(struct switch_args_t));
    args->password = DEFAULT_PASSWORD;
    args->if_local_network = 0;
    args->if_default_network = 0;
    args->mtu = 1360;
    args->pid_file = "/var/run/simplevpn.pid";
    args->log_file = "/var/run/simplevpn.log";

    while((ch = getopt(argc, argv, "l:r:L:R:p:n:g:k:e:d:s:tvh")) != -1) {
        switch(ch) {
        case 'L':
            args->local_addr[args->local_count].if_tcp = 1;
        case 'l':
            if (sscanf(optarg, "[%[^]]]:%s", args->local_addr[args->local_count].host,
             args->local_addr[args->local_count].port) == 2) {
                args->local_count++;
                args->ipv6 = 1;
            } else if (sscanf(optarg, "%[^:]:%s", args->local_addr[args->local_count].host,
             args->local_addr[args->local_count].port) == 2) {
                args->local_count++;
            } else {
                APP_ERROR("failed to parse local address\n");
            }
            break;
        case 'R':
            args->server_addr[args->server_count].if_tcp = 1;
        case 'r':
            if (sscanf(optarg, "[%[^]]]:%s", args->server_addr[args->server_count].host,
             args->server_addr[args->server_count].port) == 2) {
                args->server_count++;
                args->ipv6 = 1;
            } else if (sscanf(optarg, "%[^:]:%s", args->server_addr[args->server_count].host,
             args->server_addr[args->server_count].port) == 2) {
                args->server_count++;
            } else {
                APP_ERROR("failed to parse remote address\n");
            }
            break;
        case 'p':
            if (sscanf(optarg, "%[^/]/%u", args->prefixs[args->prefix_count].prefix,
             &args->prefixs[args->prefix_count].len) == 2) {
                if (args->prefixs[args->prefix_count].len > 32) {
                    args->prefixs[args->prefix_count].len = 32;
                }
                args->prefix_count++;
            } else {
                APP_ERROR("failed to parse prefix address\n");
            }
            break;
        case 'n':
            if (sscanf(optarg, "%[^:]", args->local_network) == 1) {
                args->if_local_network++;
            } else {
                APP_ERROR("failed to parse local network address\n");
            }
            break;
        case 'g':
            if (sscanf(optarg, "%[^:]", args->default_network) == 1)  {
                args->if_default_network++;
            } else {
                APP_ERROR("failed to parse default network address\n");
            }
            break;
        case 'k':
            args->password = strdup(optarg);
            break;
        case 'e':
            log_level = atoi(optarg);
            if (log_level > log_end)
                log_level = log_end;
            else if (log_level < log_never)
                log_level = log_never;
            break;
        case 't':
            args->has_tap = 1;
            break;
        case 'd':
            if(strcmp(optarg, "start") == 0) {
                args->cmd = SWITCH_CMD_START;
            } else if(strcmp(optarg, "stop") == 0) {
                args->cmd = SWITCH_CMD_STOP;
            } else if(strcmp(optarg, "restart") == 0) {
                args->cmd = SWITCH_CMD_RESTART;
            } else {
                APP_ERROR("unknown mode option :%s\n", optarg);
                usage();
                exit(-1);
            }
            log_level = log_warn;
            break;
        case 's':
            if (sscanf(optarg, "%d", &block_size) != 1) {
                block_size = args->mtu;
            }
            exit(crypto_speed_test(block_size));
        case 'v':
        case 'h':
            usage();
            exit(0);
        case '?': // 输入未定义的选项, 都会将该选项的值变为 ?
            APP_ERROR("unknown option \n");
            usage();
            exit(-1);
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct switch_args_t args;

    APP_INFO("%s build: %s, %s\n", argv[0], __DATE__, __TIME__);

    signal(SIGPIPE, SIG_IGN);

    if (args_parse(&args, argc, argv) < 0) {
        exit(-1);
    }

    if (!args.local_count && !args.has_tap && !args.server_count) {
        usage();
        exit(0);
    }

    if (SWITCH_CMD_START == args.cmd) {
        if (daemon_start(&args) < 0) {
            APP_ERROR("can not start daemon\n");
            exit(-1);
        }
    } else if (SWITCH_CMD_STOP == args.cmd) {
        if (daemon_stop(&args) < 0) {
            APP_ERROR("can not stop daemon\n");
            exit(-1);
        }
        // always exit if we are exec stop cmd
        return 0;
    } else if (SWITCH_CMD_RESTART == args.cmd) {
        if (daemon_stop(&args) < 0) {
            APP_ERROR("can not stop daemon\n");
            exit(-1);
        }
        if (daemon_start(&args) < 0) {
            APP_ERROR("can not start daemon\n");
            exit(-1);
        }
    }

    for (int i = 0; i < args.local_count; i++) {
        APP_INFO("bind: %s://%s:%s\n", args.local_addr[i].if_tcp?"tcp":"udp", args.local_addr[i].host, args.local_addr[i].port);
    }
    for (int i = 0; i < args.server_count; i++) {
        APP_INFO("remote: %s://%s:%s\n", args.server_addr[i].if_tcp?"tcp":"udp", args.server_addr[i].host, args.server_addr[i].port);
    }
    if (args.if_local_network) {
        APP_INFO("local device address: %s\n", args.local_network);
    }
    for (int i = 0; i < args.prefix_count; i++) {
        APP_INFO("export prefix: %s/%u\n", args.prefixs[i].prefix, args.prefixs[i].len);
    }
    if (args.if_default_network) {
        APP_INFO("default gateway: %s\n", args.default_network);
    }
#ifdef USE_CRYPTO
    if (strcmp(args.password, DEFAULT_PASSWORD) == 0) {
        APP_WARN("no encryption\n");
    }
#else
    APP_WARN("no encryption support\n");
#endif

    APP_INFO("switch running...\n");
    return switch_run(&args);
}
