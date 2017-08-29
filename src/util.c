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
#include <stdlib.h>
#include <string.h>

 
static char* itoax[256] = {
	"%00", "%01", "%02", "%03", "%04", "%05", "%06", "%07", "%08", "%09", 
	"%0A", "%0B", "%0C", "%0D", "%0E", "%0F", "%10", "%11", "%12", "%13", 
	"%14", "%15", "%16", "%17", "%18", "%19", "%1A", "%1B", "%1C", "%1D", 
	"%1E", "%1F", "%20", "%21", "%22", "%23", "%24", "%25", "%26", "%27", 
	"%28", "%29", "%2A", "%2B", "%2C", "%2D", "%2E", "%2F", "%30", "%31", 
	"%32", "%33", "%34", "%35", "%36", "%37", "%38", "%39", "%3A", "%3B", 
	"%3C", "%3D", "%3E", "%3F", "%40", "%41", "%42", "%43", "%44", "%45", 
	"%46", "%47", "%48", "%49", "%4A", "%4B", "%4C", "%4D", "%4E", "%4F", 
	"%50", "%51", "%52", "%53", "%54", "%55", "%56", "%57", "%58", "%59", 
	"%5A", "%5B", "%5C", "%5D", "%5E", "%5F", "%60", "%61", "%62", "%63", 
	"%64", "%65", "%66", "%67", "%68", "%69", "%6A", "%6B", "%6C", "%6D", 
	"%6E", "%6F", "%70", "%71", "%72", "%73", "%74", "%75", "%76", "%77", 
	"%78", "%79", "%7A", "%7B", "%7C", "%7D", "%7E", "%7F", "%80", "%81", 
	"%82", "%83", "%84", "%85", "%86", "%87", "%88", "%89", "%8A", "%8B", 
	"%8C", "%8D", "%8E", "%8F", "%90", "%91", "%92", "%93", "%94", "%95", 
	"%96", "%97", "%98", "%99", "%9A", "%9B", "%9C", "%9D", "%9E", "%9F", 
	"%A0", "%A1", "%A2", "%A3", "%A4", "%A5", "%A6", "%A7", "%A8", "%A9", 
	"%AA", "%AB", "%AC", "%AD", "%AE", "%AF", "%B0", "%B1", "%B2", "%B3", 
	"%B4", "%B5", "%B6", "%B7", "%B8", "%B9", "%BA", "%BB", "%BC", "%BD", 
	"%BE", "%BF", "%C0", "%C1", "%C2", "%C3", "%C4", "%C5", "%C6", "%C7", 
	"%C8", "%C9", "%CA", "%CB", "%CC", "%CD", "%CE", "%CF", "%D0", "%D1", 
	"%D2", "%D3", "%D4", "%D5", "%D6", "%D7", "%D8", "%D9", "%DA", "%DB", 
	"%DC", "%DD", "%DE", "%DF", "%E0", "%E1", "%E2", "%E3", "%E4", "%E5", 
	"%E6", "%E7", "%E8", "%E9", "%EA", "%EB", "%EC", "%ED", "%EE", "%EF", 
	"%F0", "%F1", "%F2", "%F3", "%F4", "%F5", "%F6", "%F7", "%F8", "%F9", 
	"%FA", "%FB", "%FC", "%FD", "%FE", "%FF"};


/*
 * Convert A-Z characters to lowercase in-place.
 * str - a string
 */
void
lcase_en(char *str)
{
	while (*str) {
		if ((*str >= 65) && (*str <= 90))
			*str = *str + 32;
		str++;
	}
}

/*
 * Convert character to lowercase and check bad characters existence.
 * name - a domain name
 *
 * return:
 *   0 - everything is ok
 *  -1 - bad character found
 */
int
normalize_and_check_domain_name(char *name)
{
	while (*name) {
		/* convert to lowercase */
		if ((*name >= 65) && (*name <= 90))
			*name = *name + 32;
		/* characters allowed in domain name:
		 *  - _ . : 0-9 a-z
		 */
		if ((*name != 45) &&
		    (*name != 95) &&
		    (*name != 46) &&
		    (*name != 58) &&
		    ((*name < 48) || (*name > 57)) &&
		    ((*name < 97) || (*name > 122)))
			return -1;
		name++;
	}
	return 0;
}

/*
 * Convert character to lowercase.
 * name - a domain name
 */
void
normalize_domain_name(char *name)
{
	lcase_en(name);
}

/*
 * Caller must free returned string only if pointer not equal to name!
 */
char*
normalize_uri_host(char *name, int size)
{
	int res_size = 1, res_size_remain = 0;
	char *c, *s, *res = NULL, *res_new;
	
	if (size < 0)
		abort();
	
	for(c = s = name; size > 0; size--, c++)
		/* characters allowed in unescaped form in a host name:
		 *  - . _ ~ ! $ & ' ( ) * + , ; = 0-9 a-z
		 */
		if ((*c != 45) &&
		    (*c != 46) &&
		    (*c != 95) &&
		    (*c != 126) &&
		    (*c != 33) &&
		    (*c != 36) &&
		    ((*c < 38) || (*c > 44)) &&
		    (*c != 59) &&
		    (*c != 61) &&
		    ((*c < 48) || (*c > 57)) &&
		    ((*c < 97) || (*c > 122))) {
			if (res_size_remain < (c - s + 3)) {
				res_size_remain += c - s + 3;
				res_size += c - s + 3;
				res_new = realloc(res, res_size);
				if (!res_new) {
					free(res);
					return NULL;
				}
				if (!res)
					res_new[0] = '\0';
				res = res_new;
			}
			strncat(res, s, c - s);
			strcat(res, itoax[(int)*c]);
			res_size_remain -= c - s + 3;
			s = c + 1;
		}
	if (!res)
		return name;

	if (res_size_remain < (c - s)) {
		res_size += c - s;
		res_new = realloc(res, res_size);
		if (!res_new) {
			free(res);
			return NULL;
		}
		res = res_new;
	}
	strncat(res, s, c - s);
	return res;
}
