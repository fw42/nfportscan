DEBUG = 1

CFLAGS += -g -Wall -std=gnu99 -O2

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

nfportscan: file.o list.o

testlist: list.o

clean:
	rm -f nfportscan *.o
