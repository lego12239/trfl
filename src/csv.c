/*
 * CSV (rfc4180) library
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
#include <stdlib.h>
#include <string.h>
#include "csv.h"


static const char eor_default[] = "\x0d\x0a";
static const char sep_default[] = ",";
static const char quote_default[] = "\"";


static int _csv_enlarge_buf(struct csv *csv);
static int _csv_enlarge_fields(struct csv *csv);
static int _csv_push_to_buf(struct csv *csv, char c);
static int _csv_pop_from_buf(struct csv *csv, unsigned int n);
static int _csv_push_to_fields(struct csv *csv);


static void
_csv_reset(struct csv *csv)
{
	csv->eor_pos = 0;
	csv->sep_pos = 0;
	csv->quote_pos = 0;
	csv->buf_pos = 0;
	csv->rec.fields_num = 0;
}

/*
 * Initialize csv structure.
 * Must be called first, before any use of csv structure or csv functions.
 * csv - a pointer to a csv structure
 */
void
csv_init(struct csv *csv)
{
	csv->eor = eor_default;
	csv->sep = sep_default;
	csv->quote = quote_default;
	csv->buf = NULL;
	csv->buf_size = 0;
	csv->rec.fields = NULL;
	csv->rec.fields_size = 0;
	_csv_reset(csv);
}

void
csv_free_buffers(struct csv *csv)
{
	if (csv->buf)
		free(csv->buf);
	csv->buf = NULL;
	csv->buf_size = 0;
	if (csv->rec.fields)
		free(csv->rec.fields);
	csv->rec.fields_num = 0;
	csv->rec.fields_size = 0;
}

/*
 * Read a token in str no more than n bytes.
 * f - a stream to read characters from
 * buf - a destination buffer to place zero-terminated token
 * buf_size - a destination buffer size
 *
 * return:
 *   0 - token is read(no error)
 *   1 - a stream read error is occured
 *   2 - eof
 *   3 - buf/fields realloc error(no mem)
 */
int
csv_read_next_rec(struct csv *csv, FILE *f)
{
	int c, is_quoted = 0, prev_is_quote = 0;
	int state = 0; /* 0 - field start, 1 - field, 2 - EOR */
	
	if (!csv->buf)
		if (_csv_enlarge_buf(csv) != 0)
			return 3;
	if (!csv->rec.fields)
		if (_csv_enlarge_fields(csv) != 0)
			return 3;
	
	_csv_reset(csv);
	if (_csv_push_to_fields(csv) != 0)
		return 3;
	
	while ((state < 2) && ((c = fgetc(f)) != -1)) {
		if (_csv_push_to_buf(csv, (char)c) != 0)
			return 3;
		switch (state) {
		case 0:
			state = 1;
			if (csv->quote_pos == -1) {
				is_quoted = 1;
				_csv_pop_from_buf(csv, strlen(csv->quote));
				break;
			}
		case 1:
			if (is_quoted) {
				if (csv->quote_pos == -1) {
					if (prev_is_quote) {
						prev_is_quote = 0;
					} else {
						_csv_pop_from_buf(csv, strlen(csv->quote));
						prev_is_quote = 1;
					}
					break;
				} else {
					if (prev_is_quote) {
						prev_is_quote = 0;
						is_quoted = 0;
					} else {
						break;
					}
				}
			}
			if (csv->sep_pos == -1) {
				_csv_pop_from_buf(csv, strlen(csv->sep));
				_csv_push_to_buf(csv, '\0');
				if (_csv_push_to_fields(csv) != 0)
					return 3;
				state = 0;
				break;
			}
			if (csv->eor_pos == -1) {
				_csv_pop_from_buf(csv, strlen(csv->eor));
				_csv_push_to_buf(csv, '\0');
				state = 2;
				break;
			}
			break;
		}
	}
	if (c == -1) {
		if (ferror(f))
			return 1;
		if (state == 0)
			return 2;
		/* state == 1 && feof(f) */
		_csv_push_to_buf(csv, '\0');
	}
	
	return 0;
}

/*
 * Add a specified character to the buffer.
 * Enlarge the buffer if needed.
 * Check eor, sep or quote match.
 * csv - a csv structure
 * c - a character to add
 *
 * return:
 *   0 - everything is ok
 *   1 - memory error on buffer enlarge
 */
static int
_csv_push_to_buf(struct csv *csv, char c)
{
	if (csv->buf_pos == csv->buf_size)
		if (_csv_enlarge_buf(csv) != 0)
			return 1;
	csv->buf[csv->buf_pos] = c;
	csv->buf_pos++;
	
	if (csv->eor_pos == -1)
		csv->eor_pos = 0;
	if (csv->eor[csv->eor_pos] == c) {
		if (csv->eor[csv->eor_pos + 1] == '\0')
			csv->eor_pos = -1;
		else
			csv->eor_pos++;
	} else {
		csv->eor_pos = 0;
	}
	if (csv->sep_pos == -1)
		csv->sep_pos = 0;
	if (csv->sep[csv->sep_pos] == c) {
		if (csv->sep[csv->sep_pos + 1] == '\0')
			csv->sep_pos = -1;
		else
			csv->sep_pos++;
	} else {
		csv->sep_pos = 0;
	}
	if (csv->quote_pos == -1)
		csv->quote_pos = 0;
	if (csv->quote[csv->quote_pos] == c) {
		if (csv->quote[csv->quote_pos + 1] == '\0')
			csv->quote_pos = -1;
		else
			csv->quote_pos++;
	} else {
		csv->quote_pos = 0;
	}
	
	return 0;
}

/*
 * Remove last n bytes from the buffer.
 * csv - a csv structure
 * n - number of bytes to remove from the tail of the buffer
 *
 * return:
 *   0 - everything is ok
 *   1 - specified number of characters is bigger than buffer
 */
static int
_csv_pop_from_buf(struct csv *csv, unsigned int n)
{
	if (n > csv->buf_pos)
		return 1;
	csv->buf_pos -= n;
	return 0;
}

/*
 * Add a pointer to a current buf position to fields.
 * Enlarge the fields if needed.
 * csv - a csv structure
 *
 * return:
 *   0 - everything is ok
 *   1 - memory error on buffer enlarge
 */
static int
_csv_push_to_fields(struct csv *csv)
{
	if (csv->rec.fields_num == csv->rec.fields_size)
		if (_csv_enlarge_fields(csv) != 0)
			return 1;
	csv->rec.fields[csv->rec.fields_num] = &csv->buf[csv->buf_pos];
	csv->rec.fields_num++;
	return 0;
}

static int
_csv_enlarge_buf(struct csv *csv)
{
	char *new_buf;
	int i;
	
	csv->buf_size += 100;
	new_buf = (char*)realloc(csv->buf, csv->buf_size * sizeof(*csv->buf));
	if (!new_buf) {
		csv->buf_size -= 100;
		return 1;
	}
	for(i = 0; i < csv->rec.fields_num; i++)
		csv->rec.fields[i] = new_buf + (csv->rec.fields[i] - csv->buf);
	csv->buf = new_buf;
	return 0;
}

static int
_csv_enlarge_fields(struct csv *csv)
{
	csv->rec.fields_size += 10;
	csv->rec.fields = (char**)realloc(csv->rec.fields,
	  csv->rec.fields_size * sizeof(*csv->rec.fields));
	if (!csv->rec.fields)
		return 1;
	return 0;
}
