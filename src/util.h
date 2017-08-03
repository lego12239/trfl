#ifndef __UTIL_H__
#define __UTIL_H__


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

#endif /* __UTIL_H__ */