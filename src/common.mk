CFLAGS += -Wall -I..

ifdef DEBUG
	CFLAGS := $(CFLAGS) -g3 -ggdb -DDEBUG
endif

.PHONY: build build-extra clean clean-extra

build: build-extra $(TARGET)

build-extra:

clean: clean-extra
	rm -f *~ *.o

clean-extra:

%.a: $(OBJS)
	$(AR) rvs $@ $^

%.o: %.c
	$(CC) -c -o $@ $(CFLAGS) $<
