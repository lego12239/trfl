#ifndef __MAIN_H__
#define __MAIN_H__

#include <pthread.h>


struct global_opts {
	unsigned int is_debug;
	unsigned int is_foreground;
	unsigned int qn_first;
	unsigned int qn_last;
	const char *pidfile_name;
	const char *conf_name;
};

struct thread_data {
	pthread_t id;
	unsigned int idx;
	unsigned int nfq_num;
	int ret;
};


extern __thread unsigned int thread_idx;


#endif /* __MAIN_H__ */