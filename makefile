LDLIBS=-lpcap -pthread

all: arp-spoof

# main.o: pch.h mac.h ip.h ethhdr.h arphdr.h arp_spoof.h main.cpp
# arp_spoof.o: pch.h mac.h ip.h ethhdr.h arphdr.h arp_spoof.h arp_spoof.cpp
# arphdr.o: pch.h mac.h ip.h arphdr.h arphdr.cpp
# ethhdr.o: pch.h mac.h ethhdr.h ethhdr.cpp
# global.o: mac.h ip.h pch.h global.h global.cpp
# ip.o: pch.h ip.h ip.cpp
# mac.o : pch.h mac.h mac.cpp
# pch.o : pch.h pch.cpp

arp-spoof: main.o arp_spoof.o arphdr.o ethhdr.o ip.o mac.o pch.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o
 