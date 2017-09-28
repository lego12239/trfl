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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include "log.h"
#include "csv.h"
#include "filters.h"
#include "elist.h"
#include "conf.h"


struct conf *conf;
pthread_mutex_t conf_mut;


static int read_statement(FILE *f, char *statement, char *ffname, char *act, char *mark);
static int read_token(FILE *f, char *str, unsigned int n);
static struct elist* conf_load_list(char *fname, char *act, char *mark);
static struct elist* _elist_make(char *name, char *fname, char *act, char *mark);
static void conf_add_elist_chain(struct conf *c, struct elist_chain *elchain);
static void _conf_stat_out(struct conf *c);
static void _conf_replace(struct conf *c);
static char* _get_list_absfname(char *absname, int size, char *conf_name, char *list_name);


static struct conf*
_conf_make(void)
{
	struct conf *c;
	
	c = malloc(sizeof(*c));
	if (!c)
		return NULL;
	memset(c, 0, sizeof(*c));
	
	return c;
}

static void
_conf_free(struct conf *c)
{
	DBG_OUT("free config...");
	elist_chain_free(c->elist_chain);
	free(c);
}

int
conf_init(void)
{
	int ret;
	
	ret = pthread_mutex_init(&conf_mut, NULL);
	if (ret != 0) {
		ERR_OUT("Mutex initialization error: %s", strerror(ret));
		return -1;
	}
	
	return 0;
}

int
conf_parse(const char * const fname)
{
	FILE *f;
	char statement[11], ffname[101], act[11], mark[11], list_absfname[1024];
	char *absname;
	struct elist *elist;
	struct elist_chain *elchain;
	struct conf *c;
	
	c = _conf_make();
	if (!c)
		return -1;
	elchain = elist_chain_make();
	if (!elchain)
		goto err_free_conf;
	conf_add_elist_chain(c, elchain);

	f = fopen(fname, "r");
	if (!f) {
		ERR_OUT("Can't open file: %s: %s", fname, strerror(errno));
		goto err_free_elchain;
	}
	while (read_statement(f, statement, ffname, act, mark) != 2) {
		if (strcmp(statement, "list") == 0) {
			absname = _get_list_absfname(list_absfname, 1024, (char*)fname,
			  ffname);
			if (!absname)
				goto err_close_file;
			elist = conf_load_list(absname, act, mark);
			if (!elist)
				goto err_close_file;
			if (!elchain->elist_first)
				elchain->elist_first = elist;
			else
				elist_add(elchain->elist_first, elist);
		} else {
			ERR_OUT("Config error: unknown statement: %s", statement);
			goto err_close_file;
		}
	}
	fclose(f);
	
	INFO_OUT("config is loaded successfully");
	_conf_stat_out(c);
	_conf_replace(c);

	return 0;
err_close_file:
	fclose(f);
err_free_elchain:
	elist_chain_free(elchain);
err_free_conf:
	free(c);
	return -1;
}

static int
read_statement(FILE *f, char *statement, char *ffname, char *act, char *mark)
{
	int ret;
	
	ret = read_token(f, statement, 11);
	if (ret == 2)
		return 2;
	ret = read_token(f, ffname, 101);
	if (ret != 0) {
		ERR_OUT("Config read error");
		exit(2);
	}
	ret = read_token(f, act, 11);
	if (ret != 0) {
		ERR_OUT("Config read error");
		exit(2);
	}
	ret = read_token(f, mark, 11);
	if (ret != 0) {
		ERR_OUT("Config read error");
		exit(2);
	}
	
	return 0;
}

/*
 * Read a token in str no more than n bytes.
 * f - a stream to read characters from
 * str - a destination buffer to place zero-terminated token
 * n - a destination buffer size
 *
 * return:
 *   0 - token is read(no error)
 *   1 - an error is occured
 *   2 - eof
 *   3 - token is incomplete(bigger buffer is needed)
 */
static int
read_token(FILE *f, char *str, unsigned int n)
{
	int c;
	unsigned int i = 0;
	unsigned state = 0; /* 0 - not started, 1 - started, 2 - finished */

	n--; /* for \0 */
	while ((state < 2) && ((c = fgetc(f)) != -1)) {
		switch (state) {
		case 0:
			if ((c == ' ') || (c == '\t') || (c == '\n'))
				break;
			state = 1;
		case 1:
			if ((c != ' ') && (c != '\t') && (c != '\n')) {
				if (i == n) {
					str[i] = '\0';
					return 3;
				}
				str[i] = c;
				i++;
				break;
			}
			state = 2;
		case 2:
			break;
		}
	}
	if (c == -1) {
		if (ferror(f))
			return 1;
		if (state == 0)
			return 2;
	}
	str[i] = '\0';

	return 0;
}

static struct elist*
conf_load_list(char *fname, char *act, char *mark)
{
	FILE *f;
	int ret, i;
	unsigned int lineno = 0;
	struct csv csv;
	struct elist *elist;
	
	elist = _elist_make("q", fname, act, mark);
	if (!elist) {
		ERR_OUT("Can't create elist for %s", fname);
		return NULL;
	}
	
	for(i = 0; filters[i]; i++) {
		ret = filters[i]->list_make(&elist->f_list[i]);
		if (ret != 0) {
			ERR_OUT("Can't create elist entry for %s filter",
			  filters[i]->name);
			goto err_free_flist;
		}
	}
	
	f = fopen(fname, "r");
	if (!f) {
		ERR_OUT("Can't open file: %s: %s", fname, strerror(errno));
		goto err_free_flist;
	}
	
	csv_init(&csv);
	csv.eor = "\n";
	csv.sep = ":";
	csv.quote = "'";
	while ((ret = csv_read_next_rec(&csv, f)) == 0) {
		lineno++;
		if (csv.rec.fields_num < 1) {
			ERR_OUT("Wrong entry format(%s:%u): too small fields number",
			  fname, lineno);
			continue;
		}
		for(i = 0; filters[i]; i++) {
			ret = filters[i]->list_entry_add(elist->f_list[i],
			  csv.rec.fields, csv.rec.fields_num);
			if (ret < 0) {
				ERR_OUT("%s filter error on adding entry(%s:%u)",
				  filters[i]->name, fname, lineno);
				goto err_cleanup_csv;
			} else if (ret == 0)
				break;
		}
		if (!filters[i]) {
			ERR_OUT("Wrong entry(%s:%u): unknown filter: %s",
			  fname, lineno, csv.rec.fields[0]);
			continue;
		}
	}
	if (ret != 2) {
		switch (ret) {
		case 1:
			if (ferror(f)) {
				ERR_OUT("File read error: %s: %s", fname, strerror(errno));
				goto err_cleanup_csv;
			}
			break;
		case 3:
			ERR_OUT("Memory error on config reading: %s", fname);
			goto err_cleanup_csv;
		}
	}
	csv_free_buffers(&csv);
	fclose(f);
	
	return elist;
	
err_cleanup_csv:
	csv_free_buffers(&csv);
	fclose(f);
err_free_flist:
	for(i = 0; filters[i]; i++)
		if (elist->f_list[i]) {
			ret = filters[i]->list_free(elist->f_list[i]);
			ERR_OUT("elist %s filter entry free error", filters[i]->name);
		}
	return NULL;
}

static struct elist*
_elist_make(char *name, char *fname, char *act, char *mark)
{
	struct elist *elist;
	char *e;
	
	elist = elist_make();
	if (!elist) {
		ERR_OUT("Can't create elist: no memory");
		return NULL;
	}
	elist->name = strdup(name);
	if (!elist->name)
		goto err_free_elist;
	elist->fname = strdup(fname);
	if (!elist->fname)
		goto err_free_elist;
	
	if (strcmp(act, "drop") == 0)
		elist->act_on_match = elist_act_drop;
	else if (strcmp(act, "accept") == 0)
		elist->act_on_match = elist_act_accept;
	else if (strcmp(act, "repeat") == 0)
		elist->act_on_match = elist_act_repeat;
	else {
		ERR_OUT("Unknown action: %s", act);
		goto err_free_elist;
	}
	
	elist->mark_on_match = strtoul(mark, &e, 10);
	if ((*e != '\0') || (e == mark)) {
		ERR_OUT("Wrong mark: %s", mark);
		goto err_free_elist;
	}
	
	return elist;

err_free_elist:
	elist_free(elist);
	return NULL;
}

static void
conf_add_elist_chain(struct conf *c, struct elist_chain *elchain)
{
	c->elist_chain = elchain;
	elchain->conf = c;
}

struct elist_chain*
conf_get_elist_chain(void)
{
	int ret;
	struct conf *c;
	
	ret = pthread_mutex_lock(&conf_mut);
	if (ret != 0) {
		ERR_OUT("conf mutex lock error: %s", strerror(ret));
		exit(2);
	}
	
	c = conf;
	c->ref_cnt++;
	
	ret = pthread_mutex_unlock(&conf_mut);
	if (ret != 0) {
		ERR_OUT("conf mutex unlock error: %s", strerror(ret));
		exit(2);
	}
	
	return c->elist_chain;
}

void
conf_release_elist_chain(struct elist_chain *elchain)
{
	int ret;
	unsigned int ref_cnt;
	struct conf *c;
	
	ret = pthread_mutex_lock(&conf_mut);
	if (ret != 0) {
		ERR_OUT("conf mutex lock error: %s", strerror(ret));
		exit(2);
	}
	
	c = (struct conf*)elchain->conf;
	ref_cnt = --c->ref_cnt;
	
	ret = pthread_mutex_unlock(&conf_mut);
	if (ret != 0) {
		ERR_OUT("conf mutex unlock error: %s", strerror(ret));
		exit(2);
	}
	
	if (ref_cnt == 0)
		_conf_free(c);
}

static void
_conf_stat_out(struct conf *c)
{
	struct elist *elist;
	struct list_item_head *lh;
	int i;
	
	list_for_each(lh, &c->elist_chain->elist_first->list) {
		elist = list_item(lh, struct elist, list);
		INFO_OUT("stat for %s list:", elist->fname);
		for(i = 0; filters[i]; i++)
			filters[i]->list_stat_out(elist->f_list[i]);
	}
}

static void
_conf_replace(struct conf *c)
{
	int ret;
	unsigned int ref_cnt;
	struct conf *old_conf;
	
	ret = pthread_mutex_lock(&conf_mut);
	if (ret != 0) {
		ERR_OUT("conf mutex lock error: %s", strerror(ret));
		exit(3);
	}
	
	old_conf = conf;
	conf = c;
	if (old_conf)
		ref_cnt = --old_conf->ref_cnt;
	else
		ref_cnt = 1;
	c->ref_cnt++;
	
	ret = pthread_mutex_unlock(&conf_mut);
	if (ret != 0) {
		ERR_OUT("conf mutex unlock error: %s", strerror(ret));
		exit(3);
	}
	
	if (ref_cnt == 0)
		_conf_free(old_conf);
}

static char*
_get_list_absfname(char *absname, int size, char *conf_name, char *list_name)
{
	char *ptr;
	
	if (list_name[0] == '/')
		return list_name;
	
	/* get a config directory name */
	ptr = rindex(conf_name, '/');
	if ((ptr - conf_name + 2) > size) {
		ERR_OUT("config path too long(>%u)", size);
		return NULL;
	}
	memcpy(absname, conf_name, ptr - conf_name + 1);
	absname[ptr - conf_name + 1] = '\0';
	
	/* append a list name */
	if ((strlen(absname) + strlen(list_name) + 1) > size) {
		ERR_OUT("config path too long(>%u)", size);
		return NULL;
	}
	strcat(absname, list_name);

	return absname;		
}

