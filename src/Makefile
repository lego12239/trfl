FILTERS := f_ipsrv f_domain f_domaintree f_uri
SRC := main.c log.c elist.c conf.c util.c csv.c avltree.c
CFLAGS := -Wall -pthread
LDFLAGS := -lnetfilter_queue -lnfnetlink $(patsubst %,-L%,$(FILTERS)) \
	$(patsubst %,-l%,$(FILTERS)) -Lpkt -lpkt -pthread

ifdef DEBUG
	CFLAGS := $(CFLAGS) -g3 -ggdb -DDEBUG
endif

.PHONY: build clean install $(FILTERS) build_pkt clean_pkt

build: trfl

trfl: build_pkt filters.o $(patsubst %.c,%.o,$(SRC)) | $(patsubst %,build_%,$(FILTERS))
	$(CC) -o $@ filters.o $(patsubst %.c,%.o,$(SRC)) $(LDFLAGS)

filters.c: gen_filters.o.sh
	./gen_filters.o.sh $(FILTERS)

install:
	install -m 555 zbwfs $(DESTDIR)/usr/sbin/

clean: $(patsubst %,clean_%,$(FILTERS)) clean_pkt
	rm -f *~ *.o filters.c

clean_pkt:
	$(MAKE) -C pkt clean

dist:
	tar -c * | xz > ../dist.txz

tags: $(SRC) $(patsubst %.c,%.h,$(SRC))
	etags $^

build_pkt:
	$(MAKE) -C pkt

build_f_%: f_%
	$(MAKE) -C $<

clean_f_%: f_%
	$(MAKE) -C $< clean

%.o: %.c
	$(CC) -c -o $@ $(CFLAGS) $<
