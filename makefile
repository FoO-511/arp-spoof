LDLIBS=-lpcap

all: arp-spoof

main.o: mac.h ip.h ethhdr.h arphdr.h arp_spoof.h main.cpp

arp_spoof.o: mac.h ip.h ethhdr.h arphdr.h arp_spoof.h arp_spoof.cpp

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

arp-spoof: main.o arp_spoof.o arphdr.o ethhdr.o ip.o mac.o 
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o
 