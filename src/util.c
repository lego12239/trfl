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
	while (*name) {
		if ((*name >= 65) && (*name <= 90))
			*name = *name + 32;
		name++;
	}
}

