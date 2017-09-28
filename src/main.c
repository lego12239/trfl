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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "main.h"
#include "log.h"
#include "elist.h"
#include "conf.h"
#include "pkt/pkt.h"
#include "filters.h"


#define VERSION "0.9.5"
#define QUEUE_MAXLEN 1024
#define CONF_NAME_LEN 1024


struct global_opts opts;
static struct thread_data *thread_data;
__thread unsigned int thread_idx;
pthread_mutex_t nfq_open_mut;

static void parse_queue_num(char *str, unsigned int *qf, unsigned int *ql);
static void output_usage(void);
static void output_version(void);
static void supervisor_stop(int exit_code, pid_t child);


static void
filters_init(void)
{
	int i;
	
	for(i = 0; filters[i]; i++)
		if (filters[i]->init() != 0) {
			ERR_OUT("Error during %s filter init", filters[i]->name);
			exit(EXIT_FAILURE);
		}
}

static char*
make_absolute_name(char *name)
{
	char *ptr, *absname;
	
	if (name[0] == '/') {
		return strdup(name);
	} else {
		absname = malloc(CONF_NAME_LEN);
		if (!absname)
			return NULL;
			
		ptr = getcwd(absname, CONF_NAME_LEN - 1);
		if (!ptr) {
			if (errno == ERANGE)
				ERR_OUT("config name too long(>%u)", CONF_NAME_LEN);
			else
				ERR_OUT("getcwd() error: %s", strerror(errno));
			goto err_cleanup;
		}
		strcat(absname, "/");
		if ((strlen(absname) + strlen(name) + 1) > CONF_NAME_LEN) {
			ERR_OUT("config name too long(>%u)", CONF_NAME_LEN);
			goto err_cleanup;
		}
		strcat(absname, name);
	}
	
	return absname;

err_cleanup:
	free(absname);
	return NULL;
}

static void
parse_opts(int argc, char **argv)
{
	int opt;
	
	while ((opt = getopt(argc, argv, "q:p:fdhv")) != -1) {
		switch (opt) {
		case 'q':
			parse_queue_num(optarg, &opts.qn_first, &opts.qn_last);
			break;
		case 'f':
			opts.is_foreground = 1;
			break;
		case 'p':
			opts.pidfile_name = optarg;
			break;
		case 'd':
			opts.is_debug = 1;
#ifndef DEBUG
			INFO_OUT("no compiled in support for -d");
#endif
			break;
		case 'h':
			output_usage();
			exit(EXIT_SUCCESS);
		case 'v':
			output_version();
			exit(EXIT_SUCCESS);
		default:
			output_usage();
			exit(EXIT_FAILURE);
		}
	}
	
	if (optind >= argc) {
		output_usage();
		exit(EXIT_FAILURE);
	}
	opts.conf_name = make_absolute_name(argv[optind]);
	if (!opts.conf_name)
		exit(1);
}

static void
parse_queue_num(char *str, unsigned int *qf, unsigned int *ql)
{
	char *s, *e;
	
	s = str;
	*qf = strtoul(s, &e, 10);
	if (((*e != '\0') && (*e != ':')) || (*qf > 65535)) {
		ERR_OUT("Wrong queues numbers format: %s", str);
		exit(EXIT_FAILURE);
	}
	
	if (*e == ':') {
		s = e + 1;
		*ql = strtoul(s, &e, 10);
		if ((*e != '\0') || (*ql > 65535)) {
			ERR_OUT("Wrong queues numbers format: %s", str);
			exit(EXIT_FAILURE);
		}
	} else {
		*ql = *qf;
	}
	
	if (*qf > *ql) {
		ERR_OUT("First queue number is greater than last queue number");
		exit(EXIT_FAILURE);
	}
}

static void
output_usage(void)
{
	fprintf(stderr, "Usage: trfl [OPTIONS] CONF_FILE\n\n"
	  " Options:\n"
	  "  -d    Output debug messages"
#ifndef DEBUG
	  "(NO COMPILED IN SUPPORT)"
#endif
	  "\n"
	  "  -q    NFQUEUE numbers(format: FIRST[:LAST])\n"
	  "  -f    stay foreground\n"
	  "  -p    pidfile name\n"
	  "  -h    output this help\n"
	  "  -v    output version\n");
}

static void
output_version(void)
{
	printf("trfl %s\n", VERSION);
}

static void
daemonize(void)
{
	pid_t pid;
	int ret;
	
	if (opts.is_foreground)
		return;
	
	pid = fork();
	if (pid < 0) {
		ERR_OUT("daemonize error: fork() error: %s", strerror(errno));
		exit(1);
	}
	if (pid)
		exit(0);
	
	pid = setsid();
	if (pid < 0) {
		ERR_OUT("daemonize error: setsid() error: %s", strerror(errno));
		exit(1);
	}
	
	ret = chdir("/");
	if (ret < 0) {
		ERR_OUT("daemonize error: chdir() error: %s", strerror(errno));
		exit(1);
	}
	
	close(0);
	close(1);
	close(2);
	ret = open("/dev/null", O_RDWR);
	if (ret < 0) {
		ERR_OUT("daemonize error: open(/dev/null) error: %s",
		  strerror(errno));
		exit(1);
	}
	if (ret != 0) {
		ERR_OUT("daemonize error: got %d fd instead of 0", ret);
		exit(1);
	}
	ret = dup(0);
	if (ret < 0) {
		ERR_OUT("daemonize error: dup() error: %s", strerror(errno));
		exit(1);
	}
	if (ret != 1) {
		ERR_OUT("daemonize error: got %d fd instead of 1", ret);
		exit(1);
	}
	ret = dup(0);
	if (ret < 0) {
		ERR_OUT("daemonize error: dup() error: %s", strerror(errno));
		exit(1);
	}
	if (ret != 2) {
		ERR_OUT("daemonize error: got %d fd instead of 2", ret);
		exit(1);
	}
}

static void
pidfile_make(void)
{
	FILE *f;
	
	if (!opts.pidfile_name)
		return;
	
	f = fopen(opts.pidfile_name, "w");
	if (!f) {
		ERR_OUT("pidfile creation error: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
	fprintf(f, "%u\n", getpid());
	if (fclose(f) != 0) {
		ERR_OUT("pidfile closing error: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
}

static pid_t
supervisor_child_start(void)
{
	pid_t pid;
	
	pid = fork();
	if (pid < 0) {
		ERR_OUT("fork() error: %s", strerror(errno));
		supervisor_stop(1, 0);
	}
	
	return pid;
}

static int
supervisor_child_wait(pid_t child, int *ecode, int *esig)
{
	int ret, child_ret;
	
	ret = waitpid(child, &child_ret, WNOHANG);
	if (ret < 0) {
		ERR_OUT("waitpid() error: %s", strerror(errno));
		supervisor_stop(1, child);
	}
	if (ret != child) {
		ERR_OUT("waitpid() can't see a terminated child");
		supervisor_stop(1, child);
	}
	if (WIFEXITED(child_ret)) {
		*ecode = WEXITSTATUS(child_ret);
		INFO_OUT("child exited with exit code %d", *ecode);
		return 0;
	} else {
		*esig = WTERMSIG(child_ret);
		INFO_OUT("child was terminated by a signal %d", *esig);
		return 1;
	}
}

static void
supervisor_start(void)
{
	sigset_t mask;
	int ret, signo, ecode, esig;
	pid_t pid;
	
	pid = supervisor_child_start();
	if (pid == 0)
		return;
		
	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR1);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGQUIT);
	sigaddset(&mask, SIGHUP);
	sigaddset(&mask, SIGCHLD);
	
	while ((ret = sigwait(&mask, &signo)) == 0) {
		switch (signo) {
		case SIGUSR1:
			INFO_OUT("Got SIGUSR1 - send to child");
			ret = kill(pid, SIGUSR1);
			if (ret < 0) {
				ERR_OUT("Can't send signal to child: %s", strerror(errno));
				supervisor_stop(1, pid);
			}
			break;
		case SIGTERM:
		case SIGINT:
		case SIGQUIT:
		case SIGHUP:
			INFO_OUT("Got %d signal - send to child", signo);
			ret = kill(pid, SIGTERM);
			if (ret < 0) {
				ERR_OUT("Can't send signal to child: %s", strerror(errno));
				supervisor_stop(1, pid);
			}
			supervisor_stop(0, pid);
			break;
		case SIGCHLD:
			INFO_OUT("Got SIGCHLD signal");
			sleep(1);
			ret = supervisor_child_wait(pid, &ecode, &esig);
			if ((ret == 0) && (ecode == 2))
				supervisor_stop(1, 0);
			INFO_OUT("restart child");
			pid = supervisor_child_start();
			if (pid == 0)
				return;
			break;
		default:
			ERR_OUT("Got signal %d, but doesn't known how to handle it",
			  signo);
			break;
		}
	}
	ERR_OUT("sigwait() error: %s", strerror(ret));
	exit(1);
}

static void
supervisor_stop(int exit_code, pid_t child)
{
	int ret, child_ret, sec = 0;
	
	ret = killpg(0, SIGTERM);
	if (ret < 0)
		ERR_OUT("Can't send a SIGTERM signal to a process group on "
		  "supervisor stop");
	if (child == 0)
		exit(exit_code);
	
	while ((sec < 3) && ((ret = waitpid(child, &child_ret, WNOHANG)) == 0)) {
		sleep(1);
		sec++;
	}
	if (ret < 0)
		ERR_OUT("waitpid() error: %s", strerror(errno));
	if (ret != child) {
		ERR_OUT("child isn't terminated - send SIGKILL");
		killpg(0, SIGKILL);
	}
	exit(exit_code);
}

static void
sig_init(void)
{
	sigset_t mask;
	int ret;
	
	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR1);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGCHLD);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGQUIT);
	sigaddset(&mask, SIGHUP);
	ret = pthread_sigmask(SIG_BLOCK, &mask, NULL);
	if (ret != 0) {
		ERR_OUT("Initialization of signal stuff failed: %s", strerror(ret));
		exit(EXIT_FAILURE);
	}
}

static void
sig_wait_loop(void)
{
	sigset_t mask;
	int ret, signo;
	
	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR1);
	sigaddset(&mask, SIGTERM);
	
	while ((ret = sigwait(&mask, &signo)) == 0) {
		switch (signo) {
		case SIGUSR1:
			INFO_OUT("Got SIGUSR1 - reload config");
			if (conf_parse(opts.conf_name) < 0)
				ERR_OUT("config reloading error - stay with old one");
			break;
		case SIGTERM:
			INFO_OUT("Got SIGTERM - terminating");
			exit(0);
			break;
		default:
			ERR_OUT("Got signal %d, but doesn't known how to handle it",
			  signo);
			break;
		}
	}
	ERR_OUT("sigwait() error: %s", strerror(ret));
}

static int
is_pkt_match(struct pkt *pkt, enum elist_act *act, uint32_t *mark,
  enum elist_act *act_default, uint32_t *mark_default)
{
	int i, ret = 0;
	struct elist *elist;
	struct elist_chain *elchain;
	struct list_item_head *lh;
	
	elchain = conf_get_elist_chain();
	
	*act_default = elchain->act_default;
	*mark_default = elchain->mark_default;
	
	list_for_each(lh, &elchain->elist_first->list) {
		elist = list_item(lh, struct elist, list);
		for(i = 0; filters[i]; i++) {
			ret = filters[i]->filter_pkt(elist->f_list[i], pkt);
			if (ret == 1) {
				*act = elist->act_on_match;
				*mark = elist->mark_on_match;
				goto out;
			}
		}
	}
	
out:
	conf_release_elist_chain(elchain);
	
	return ret;
}

static int
cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad,
  void *data)
{
	struct nfqnl_msg_packet_hdr *ph;
	unsigned char *payload;
	struct pkt *pkt;
	unsigned int verdict = NF_ACCEPT;
	uint32_t mark = 0, mark_def;
	enum elist_act act, act_def;
	int ret;
	
	ph = nfq_get_msg_packet_hdr(nfad);
	ret = nfq_get_payload(nfad, &payload);
	if (ret < 0) {
		ERR_OUT("nfq_get_payload() error");
		return 0;
	}
	pkt = pkt_make(payload, ret, ntohl(ph->packet_id));
	if (pkt) {
		pkt_dump(pkt);
		if (!is_pkt_match(pkt, &act, &mark, &act_def, &mark_def)) {
			act = act_def;
			mark = mark_def;
		}
		switch (act) {
		case elist_act_accept:
			verdict = NF_ACCEPT;
			DBG_OUT("%u: VERDICT - ACCEPT(mark - %u)",
			  ntohl(ph->packet_id), mark);
			break;
		case elist_act_drop:
			verdict = NF_DROP;
			DBG_OUT("%u: VERDICT - DROP", ntohl(ph->packet_id));
			break;
		case elist_act_repeat:
			verdict = NF_REPEAT;
			DBG_OUT("%u: VERDICT - REPEAT(mark - %u)",
			  ntohl(ph->packet_id), mark);
			break;
		}
		pkt_free(pkt);
	}

	ret = nfq_set_verdict2(qh, ntohl(ph->packet_id), verdict, mark, 0, NULL);
	if (ret < 0)
		ERR_OUT("nfq_set_verdict() error");
	
	return ret;
}

static void
threads_init(void)
{
	unsigned int n, i;
	
	n = opts.qn_last - opts.qn_first + 1;
	thread_data = malloc(sizeof(*thread_data) * n);
	if (!thread_data) {
		ERR_OUT("Threads init error: no memory");
		exit(EXIT_FAILURE);
	}
	memset(thread_data, 0, sizeof(*thread_data) * n);

	for(i = 0; i < n; i++) {
		thread_data[i].idx = i;
		thread_data[i].nfq_num = opts.qn_first + i;
	}
}

static struct nfq_handle*
init_nfq(unsigned int nfq_num)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int size, ret;
	
	ret = pthread_mutex_lock(&nfq_open_mut);
	if (ret != 0) {
		ERR_OUT("nfq_open mutex lock error: %s", strerror(ret));
		exit(EXIT_FAILURE);
	}
	h = nfq_open();
	if (!h) {
		ERR_OUT("thread %u: nfq error: queue %d nfq_open() error",
		  thread_idx, nfq_num);
		exit(EXIT_FAILURE);
	}
	ret = pthread_mutex_unlock(&nfq_open_mut);
	if (ret != 0) {
		ERR_OUT("nfq_open mutex unlock error: %s", strerror(ret));
		exit(EXIT_FAILURE);
	}
	
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		ERR_OUT("thread %u: nfq error: queue %d nfq_bind_pf() error",
		  thread_idx, nfq_num);
		exit(EXIT_FAILURE);
	}
	if (nfq_bind_pf(h, AF_INET) < 0) {
		ERR_OUT("thread %u: nfq error: queue %d nfq_bind_pf() error",
		  thread_idx, nfq_num);
		exit(EXIT_FAILURE);
	}
	qh = nfq_create_queue(h, nfq_num, &cb, NULL);
	if (!qh) {
		ERR_OUT("thread %u: nfq error: queue %d nfq_create_queue() error",
		  thread_idx, nfq_num);
		exit(EXIT_FAILURE);
	}
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		ERR_OUT("thread %u: nfq error: queue %d nfq_set_mode() error",
		  thread_idx, nfq_num);
		exit(EXIT_FAILURE);
	}

	size = nfq_set_queue_maxlen(qh, QUEUE_MAXLEN);
	if (size < 0)
		INFO_OUT("thread %u: nfq: try to set queue maxlen, but fail: "
		  "no kernel support?", thread_idx);
	else
		INFO_OUT("thread %u: nfq: set queue maxlen to %u packets",
		  thread_idx, QUEUE_MAXLEN);

	size = nfnl_rcvbufsiz(nfq_nfnlh(h), 1500 * QUEUE_MAXLEN);
	INFO_OUT("thread %u: nfq: set receive buffer size to %u "
	  "bytes(request %u)", thread_idx, size, 1500 * QUEUE_MAXLEN);
	
	size = 1;
	ret = setsockopt(nfq_fd(h), SOL_NETLINK, NETLINK_NO_ENOBUFS, &size,
	  sizeof(size));
	if (ret != 0) {
		ERR_OUT("setsockopt() error: %s", strerror(ret));
		exit(EXIT_FAILURE);
	}
	
	return h;
}

static void*
thread_start(void *data)
{
	struct nfq_handle *h;
	int fd, n;
	char *pkt_buf;
	struct thread_data *td = (struct thread_data*)data;

	thread_idx = td->idx;

	INFO_OUT("start thread %u[%u] for nfqueue %u", thread_idx,
	  syscall(SYS_gettid), td->nfq_num);
	
	pkt_buf = malloc(80000);
	if (!pkt_buf) {
		ERR_OUT("packet buffer allocating error: no memory");
		exit(EXIT_FAILURE);
	}
	h = init_nfq(td->nfq_num);
	fd = nfq_fd(h);
	while ((n = recv(fd, pkt_buf, 80000, 0)) > 0) {
		nfq_handle_packet(h, pkt_buf, n);
	}
	ERR_OUT("recv error: %s", strerror(errno));
	if (nfq_close(h) != 0) {
		ERR_OUT("nfq_close() error");
		exit(EXIT_FAILURE);
	}
	
	return NULL;
}

int
main(int argc, char **argv)
{
	int i, ret;
	pthread_attr_t attr;
	
	log_init("trfl-SV");
	parse_opts(argc, argv);
	daemonize();
	/* The order of 3 next calls is important! */
	pidfile_make();
	sig_init();
	supervisor_start();
	log_deinit();
	log_init("trfl");
	
	pkt_init();
	filters_init();
	if (conf_init() < 0)
		exit(2);
	if (conf_parse(opts.conf_name) < 0)
		exit(2);
	
	threads_init();

	if (setpriority(PRIO_PROCESS, 0, -18) != 0)
		ERR_OUT("setpriority() error(want %d priority): %s", -18,
		  strerror(errno));

	ret = pthread_mutex_init(&nfq_open_mut, NULL);
	if (ret != 0) {
		ERR_OUT("nfq_open mutex initialization error: %s", strerror(ret));
		exit(EXIT_FAILURE);
	}
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	for(i = 0; i <= (opts.qn_last - opts.qn_first); i++) {
		ret = pthread_create(&(thread_data[i].id), &attr, thread_start,
		  &thread_data[i]);
		if (ret != 0) {
			ERR_OUT("thread creation error: %s", strerror(ret));
			exit(EXIT_FAILURE);
		}
	}
	pthread_attr_destroy(&attr);
	
	sig_wait_loop();
	
	return 0;
}
