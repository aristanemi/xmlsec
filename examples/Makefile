#
#
#
PROGRAMS = \
	sign1 xpath1
CC	= gcc
CFLAGS	+= -g $(shell xmlsec1-config --cflags) -DUNIX_SOCKETS -Wall -Wextra -Wl,-rpath=/usr/local/lib -g
LDLIBS	+= -g $(shell xmlsec1-config --libs)

all: $(PROGRAMS)

clean:
	rm -rf $(PROGRAMS)

check: $(PROGRAMS)
	./sign1    sign1-tmpl.xml    rsakey.pem

