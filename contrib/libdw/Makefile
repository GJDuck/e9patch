CC=gcc
CFLAGS = -fPIC -Os -I. -Iinclude/ -D HAVE_CONFIG_H

SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)

libdw.a: $(OBJS)
	ar rvs libdw.a $(OBJS)

clean:
	rm -rf $(OBJS) libdw.a

