
WIRESHARK_CFLAGS=$(shell pkg-config wireshark --cflags)
WIRESHARK_LIBS=$(shell pkg-config wireshark --cflags --libs)

CFLAGS=$(WIRESHARK_CFLAGS) -Wall -Werror -O2 -std=c99 -fPIC
LDFLAGS=$(WIRESHARK_LIBS) -Wl,--no-undefined

WIRESHARK_VER=4.0
WIRESHARK_PUGINS=~/.local/lib/wireshark/plugins/$(WIRESHARK_VER)/epan

OUTFILE=build/rssi.so

all: $(OUTFILE)

clean:
	rm -rf build

.PHONY: clean

$(OUTFILE): src/ws-rssi.c
	@mkdir -p build
	$(CC) -shared -o $@ $(CFLAGS) src/ws-rssi.c $(LDFLAGS)

install: $(OUTFILE)
	cp -fv $(OUTFILE) $(WIRESHARK_PUGINS)/rssi.so
