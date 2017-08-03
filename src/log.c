/*
 * traffic filter
 * Copyright (C) 2017, Oleg Nemanov <lego12239@yandex.ru>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <syslog.h>
#include <stdarg.h>
#include "main.h"
#include "log.h"


extern struct global_opts opts;

void
log_init(const char * const prg_name)
{
	openlog(prg_name, LOG_PID, LOG_USER);
}

void
log_deinit(void)
{
	closelog();
}

void
verr_out(const char * const fmt, va_list ap)
{
	va_list ap1;
	
	va_copy(ap1, ap);
	vsyslog(LOG_ERR, fmt, ap1);
	va_end(ap1);
	va_copy(ap1, ap);
	vfprintf(stderr, fmt, ap1);
	va_end(ap1);
}

void
err_out(const char * const fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	verr_out(fmt, ap);
	va_end(ap);
}

void
vinfo_out(const char * const fmt, va_list ap)
{
	va_list ap1;
	
	va_copy(ap1, ap);
	vsyslog(LOG_INFO, fmt, ap1);
	va_end(ap1);
	va_copy(ap1, ap);
	vprintf(fmt, ap1);
	va_end(ap1);
}

void
info_out(const char * const fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vinfo_out(fmt, ap);
	va_end(ap);
}

void
vdbg_out(const char * const fmt, va_list ap)
{
	va_list ap1;
	
	if (!opts.is_debug)
		return;
	
	va_copy(ap1, ap);
	vsyslog(LOG_DEBUG, fmt, ap1);
	va_end(ap1);
	va_copy(ap1, ap);
	vprintf(fmt, ap1);
	va_end(ap1);
}

void
dbg_out(const char * const fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vdbg_out(fmt, ap);
	va_end(ap);
}

void
any_out(int lvl, const char * const fmt, ...)
{
	va_list ap;
	
	va_start(ap, fmt);
	switch (lvl) {
	case OUTLVL_ERR:
		verr_out(fmt, ap);
		break;
	case OUTLVL_INFO:
		vinfo_out(fmt, ap);
		break;
	case OUTLVL_DBG:
		vdbg_out(fmt, ap);
		break;
	default:
		err_out("wrong output level %d for %s", lvl, fmt);
		break;
	}
	va_end(ap);
}
