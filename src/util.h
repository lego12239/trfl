#ifndef __UTIL_H__
#define __UTIL_H__


/*
 * Convert A-Z characters to lowercase in-place.
 * str - a string
 */
void lcase_en(char *str);
/*
 * Convert character to lowercase and check bad characters existence.
 * name - a domain name
 *
 * return:
 *   0 - everything is ok
 *  -1 - bad character found
 */
int normalize_and_check_domain_name(char *name);
/*
 * Convert character to lowercase.
 * name - a domain name
 */
void normalize_domain_name(char *name);

/*
 * Caller must free returned string only if pointer not equal to name!
 */
char* normalize_uri_host(char *name, int size);

#endif /* __UTIL_H__ */