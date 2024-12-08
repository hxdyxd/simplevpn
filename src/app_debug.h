#ifndef _APP_DEBUG_H
#define _APP_DEBUG_H

#include <stdio.h>
#include <syslog.h>
#include <sys/time.h>
#include "log.h"


#define PRINTF(...) printf(__VA_ARGS__)

#ifdef HAVE_ANDROID_LOG
#include <android/log.h>

#define APP_ERROR(s...) \
    __android_log_print(ANDROID_LOG_ERROR, __FILE__, s)
#define APP_WARN(s...) \
    __android_log_print(ANDROID_LOG_WARN, __FILE__, s)
#define APP_INFO(s...) \
    __android_log_print(ANDROID_LOG_INFO, __FILE__, s)
#define APP_DEBUG(s...) \
    __android_log_print(ANDROID_LOG_DEBUG, __FILE__, s)
#define APP_TRACE(s...) \
    __android_log_print(ANDROID_LOG_VERBOSE, __FILE__, s)

#else
#define APP_ERROR(...) mylog(log_error, __VA_ARGS__)
#define APP_WARN(...) mylog(log_warn, __VA_ARGS__)
#define APP_INFO(...) mylog(log_info, __VA_ARGS__)
#define APP_DEBUG(...) mylog(log_debug, __VA_ARGS__)
#define APP_TRACE(...) mylog(log_trace, __VA_ARGS__)
#endif

#endif
