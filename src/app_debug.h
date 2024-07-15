#ifndef _APP_DEBUG_H
#define _APP_DEBUG_H

#include <stdio.h>
#include <syslog.h>
#include <sys/time.h>
#include "log.h"


#define PRINTF(...) printf(__VA_ARGS__)

#define APP_ERROR(...) mylog(log_error, __VA_ARGS__)

#define APP_WARN(...) mylog(log_warn, __VA_ARGS__)

#define APP_INFO(...) mylog(log_info, __VA_ARGS__)

#define APP_DEBUG(...) mylog(log_debug, __VA_ARGS__)

#define APP_TRACE(...) mylog(log_trace, __VA_ARGS__)

#endif
