-include config.mk

CFLAGS += -g -Wall -std=gnu99 -O2
LDFLAGS += -ladns

ifeq ($(DEBUG),1)
	CFLAGS += -Wall -W -Wchar-subscripts -Wmissing-prototypes
	CFLAGS += -Wmissing-declarations -Wredundant-decls
	CFLAGS += -Wstrict-prototypes -Wshadow -Wbad-function-cast
	CFLAGS += -Winline -Wpointer-arith -Wsign-compare
	CFLAGS += -Wunreachable-code -Wdisabled-optimization
	CFLAGS += -Wcast-align -Wwrite-strings -Wnested-externs -Wundef
	CFLAGS += -DDEBUG
endif

.PHONY: all clean

all: nfportscan

nfportscan: file.o list.o nftree.o grammar.o scanner.o util.o ipconv.o nf_common.o

nftree.o: grammar.c grammar.h

grammar.c grammar.h: grammar.y
	bison -y -d -v $<
	mv y.tab.c grammar.c
	mv y.tab.h grammar.h

scanner.c: scanner.l
	flex -i scanner.l
	mv lex.yy.c scanner.c

scanner.o: grammar.h

clean:
	rm -f nfportscan *.o
	rm -f y.output grammar.h grammar.c y.tab.c y.tab.h
	rm -f scanner.c lex.yy.c

.PHONY: snapshot

snapshot:
DESC=$(shell git describe)

snapshot:
	git archive --format=tar --prefix=nfportscan-$(DESC)/ HEAD | gzip > ../nfportscan-$(DESC).tar.gz
