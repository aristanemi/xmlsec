#
#
#
PROGRAMS = \
	sign1 sign2 sign3 \
	verify1 verify2 verify3 verify4 \
	encrypt1 encrypt2 encrypt3 \
	decrypt1 decrypt2 decrypt3 \
	xmldsigverify

CC	= gcc
CFLAGS	+= -g $(shell xmlsec1-config --cflags) -DUNIX_SOCKETS -Wall -Wextra -Wl,-rpath=/usr/local/lib -g
LDLIBS	+= -g $(shell xmlsec1-config --libs)

all: $(PROGRAMS)

clean:
	rm -rf $(PROGRAMS)

check: $(PROGRAMS)
	./sign1    sign1-tmpl.xml    rsakey.pem

