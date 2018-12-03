PREFIX=/usr
CFLAGS=-g3 -fPIC -Wall $(shell pkg-config --cflags gnutls glib-2.0)
LIBS=$(shell pkg-config --libs gnutls glib-2.0)
all: libwebsocket.so libwebsocket.pc testclient

libwebsocket.so: websock.o
	$(CC) -shared $^ $(LIBS) -o $@

libwebsocket.pc: Makefile
	echo 'prefix=$(PREFIX)' > $@
	echo 'libdir=$${prefix}/lib' >> $@
	echo 'includedir=$${prefix}/include' >> $@
	echo 'Name: libwebsocket' >> $@
	echo 'Version: 0.x' >> $@
	echo 'Description: an implementation of websockets version 13' >> $@
	echo 'Libs: -L$${libdir} -lwebsocket' >> $@
	echo 'Cflags: -I$${includedir}' >> $@

testclient: testclient.o libwebsocket.so
	$(CC) $^ -o $@

install: libwebsocket.so libwebsocket.pc
	install -m 644 websock.h -D $(PREFIX)/include/libwebsocket/websock.h
	install -m 644 libwebsocket.so -D $(PREFIX)/lib/libwebsocket.so
	install -m 644 libwebsocket.pc -D $(PREFIX)/lib/pkgconfig/libwebsocket.pc

clean:
	rm -f libwebsocket.so websock.o
