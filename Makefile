all : pcap_test

pcap_test : packet.o main.o
	gcc -lpcap -o pcap_test packet.o main.o

packet.o : packet.c packet.h
	gcc -lpcap -c -o packet.o packet.c

main.o : main.c packet.h
	gcc -lpcap -c -o main.o main.c

clean :
	rm *.o pcap_test