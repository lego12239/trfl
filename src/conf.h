#ifndef __CONF_H__
#define __CONF_H__


struct conf {
	struct elist_chain *elist_chain;
	unsigned int ref_cnt;
};


int conf_init(void);
int conf_parse(const char * const fname);
struct elist_chain* conf_get_elist_chain(void);
void conf_release_elist_chain(struct elist_chain *elchain);


#endif  /* __CONF_H__ */
