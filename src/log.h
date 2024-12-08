#ifndef LOG_MYLOG_H_
#define LOG_MYLOG_H_

#include <stdio.h>

#define RED "\x1B[31m"
#define GRN "\x1B[32m"
#define YEL "\x1B[33m"
#define BLU "\x1B[34m"
#define MAG "\x1B[35m"
#define CYN "\x1B[36m"
#define WHT "\x1B[37m"
#define RESET "\x1B[0m"

#define log_never   0
#define log_fatal   1
#define log_error   2
#define log_warn    3
#define log_info    4
#define log_debug   5
#define log_trace   6
#define log_end     7


extern int log_level;
extern int enable_log_position;
extern int enable_log_color;

#ifdef MY_DEBUG
#define mylog(__first_argu__dummy_abcde__, ...) printf(__VA_ARGS__)

#else
#define mylog(...) log0(__FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)
#endif


void log0(const char* file, const char* function, int line, int level, const char* str, ...);

void log_bare(int level, const char* str, ...);

#endif
