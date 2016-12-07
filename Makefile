kernel ?= $(shell uname -r)
kdir ?= /lib/modules/$(kernel)/build

obj-m = ptdump.o

all: ptdump.ko ptdump_cli

ptdump_cli: ptdump_cli.c
	gcc -Wall $< -o $@

ptdump.ko: ptdump.h ptdump.c
	$(MAKE) -C $(kdir) M=$$(pwd)

clean:
	rm -f *.ko *.o ptdump_cli

ifneq ($(wildcard Makefile.local),)
include Makefile.local
endif
