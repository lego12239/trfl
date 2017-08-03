#ifndef __LOG_H__
#define __LOG_H__

#include <stdarg.h>


#define OUTLVL_ERR 0
#define OUTLVL_INFO 1
#define OUTLVL_DBG 2

#define ERR_OUT(fmt, ...) err_out("%s:%u: " fmt "\n", __FILE__, __LINE__, \
  ##__VA_ARGS__)
#define INFO_OUT(fmt, ...) info_out(fmt "\n", ##__VA_ARGS__)
#ifdef DEBUG
#define DBG_OUT(fmt, ...)  dbg_out("%s:%u: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define DBG_OUT(fmt, ...)
#endif /* DEBUG */
#define ANY_OUT(lvl, fmt, ...) any_out((lvl), "%s:%u: " fmt "\n", __FILE__, __LINE__, \
  ##__VA_ARGS__)

void log_init(const char * const prg_name);
void log_deinit(void);
void verr_out(const char * const fmt, va_list ap);
void err_out(const char * const fmt, ...);
void vinfo_out(const char * const fmt, va_list ap);
void info_out(const char * const fmt, ...);
void vdbg_out(const char * const fmt, va_list ap);
void dbg_out(const char * const fmt, ...);
void any_out(int lvl, const char * const fmt, ...);

#endif /* __LOG_H__ */