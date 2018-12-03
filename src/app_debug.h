#ifndef _APP_DEBUG_H
#define _APP_DEBUG_H

#include <stdio.h>
#include <syslog.h>
#include <sys/time.h>

#define BLUE_FONT "\033[40;34m%s\033[0m "
#define RED_FONT "\033[40;31m%s\033[0m "
#define GREEN_FONT "\033[40;32m%s\033[0m "
#define YELLOW_FONT "\033[40;33m%s\033[0m "
#define PURPLE_FONT "\033[40;35m%s\033[0m "
#define DGREEN_FONT "\033[40;36m%s\033[0m "
#define WHITE_FONT "\033[40;37m%s\033[0m "


#define TIME_COUNT() (int)debug_tv.tv_sec


#define PRINTF(...) printf(__VA_ARGS__);syslog(LOG_INFO, __VA_ARGS__);

#define APP_ERROR(...) if(1) {\
					struct timeval debug_tv;gettimeofday(&debug_tv,NULL);\
					printf("\033[40;32m[%d]\033[0m \033[2;40;33m%s(%d)\033[0m: ",\
					 TIME_COUNT(), __FUNCTION__, __LINE__);\
					printf("\033[1;40;31mERROR\033[0m ");\
					printf(__VA_ARGS__);\
					syslog(LOG_ERR, __VA_ARGS__);}

#define APP_WARN(...) if(1) {\
					struct timeval debug_tv;gettimeofday(&debug_tv,NULL);\
					printf("\033[40;32m[%d]\033[0m \033[2;40;33m%s(%d)\033[0m: ",\
					TIME_COUNT(), __FUNCTION__, __LINE__);\
					printf("\033[1;40;33mWARN\033[0m ");\
					printf(__VA_ARGS__);\
					syslog(LOG_WARNING, __VA_ARGS__);}

#define APP_DEBUG(...) if(1) {\
					struct timeval debug_tv;gettimeofday(&debug_tv,NULL);\
					printf("\033[40;32m[%d]\033[0m \033[2;40;33m%s(%d)\033[0m: ",\
					 TIME_COUNT(), __FUNCTION__, __LINE__);\
					printf(__VA_ARGS__);\
					syslog(LOG_DEBUG, __VA_ARGS__);}



#endif
