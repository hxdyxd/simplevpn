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
#include "app_debug.h"
#include "simplevpn.h"

#define VERSION "0.1.2"
#define DEBUG_INFO     1
#define TIME_DEBUG    15

#define BUF_SIZE                   2000
#define DEFAULT_SERVER_HOST  "127.0.0.1"
#define DEFAULT_SERVER_PORT        2020
#define DEFAULT_PASSWORD     "12345678"
#define DEFAULT_MODE        (MODE_SWITCH)

void usage(void)
{
	PRINTF("\n");
	PRINTF("simplevpn %s\n\n", VERSION);
	PRINTF("  usage:\n\n");
	PRINTF("    simplevpn\n");
	PRINTF("\n");
	PRINTF(
		"       -s <server_host>           Host name or IP address of your remote server.\n");
	PRINTF(
		"       -p <server_port>           Port number of your remote server.\n");
	PRINTF(
		"       -k <password>              Password of your remote server.\n");
#ifndef DISABLE_CLIENT
	PRINTF(
		"       -m <mode>                  Choose switch or client mode.\n");
#else
	PRINTF(
		"                                  Only switch mode.");
#endif
	PRINTF("\n");
	PRINTF(
		"       [-v]                       Verbose mode.\n");
	PRINTF(
		"       [-h, --help]               Print this message.\n");
	PRINTF("\n");
}

int main(int argc, char **argv)
{
	char *server_host = DEFAULT_SERVER_HOST;
	int server_port = DEFAULT_SERVER_PORT;
	char *password = DEFAULT_PASSWORD;
	int mode = DEFAULT_MODE;
	int ch;

	while((ch = getopt(argc, argv, "s:p:k:m:hv")) != -1) {
		switch(ch) {
		case 's':
			server_host = optarg;
			break;
		case 'p':
			server_port = atoi(optarg);
			break;
		case 'k':
			password = optarg;
		case 'm':
			if(strcmp(optarg, "client") == 0) {
				mode = MODE_CLIENT;
			} else if(strcmp(optarg, "switch") == 0) {
				mode = MODE_SWITCH;
			} else {
				APP_ERROR("unknown mode option \n");
				usage();
				exit(-1);
			}
			break;
		case 'v':
		case 'h':
			usage();
			exit(-1);
		case '?': // 输入未定义的选项, 都会将该选项的值变为 ?
			APP_ERROR("unknown option \n");
			usage();
			exit(-1);
		}
	}

	APP_DEBUG("server address: %s:%d\n", server_host, server_port);
	if(strcmp(password, DEFAULT_PASSWORD) == 0) {
		APP_WARN("use default password: %s\n", password);
	}

	if(mode == MODE_SWITCH) {
		APP_DEBUG("switch running...\n");
		return switch_run(server_host, server_port, password);
	} else {
		APP_DEBUG("client running...\n");
		return tap_client_run(server_host, server_port, password);
	}
}
