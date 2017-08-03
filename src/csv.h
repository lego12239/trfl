#ifndef __CSV_H__
#define __CSV_H__

struct csv {
	const char *eor;
	int eor_pos;
	const char *sep;
	int sep_pos;
	const char *quote;
	int quote_pos;
	char *buf;
	int buf_pos;
	unsigned int buf_size;
	struct {
		char **fields;
		unsigned int fields_num;
		unsigned int fields_size;
	} rec;
};

/*
 * Initialize csv structure.
 * Must be called first, before any use of csv structure or csv functions.
 * csv - a pointer to a csv structure
 */
void csv_init(struct csv *csv);
void csv_free_buffers(struct csv *csv);
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
int csv_read_next_rec(struct csv *csv, FILE *f);


#endif  /* __CSV_H__ */
