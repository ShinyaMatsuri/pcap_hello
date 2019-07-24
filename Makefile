all : pcap_hello

pcap_hello : PRINT.o main.o
	g++ -g -o pcap_hello PRINT.o main.o -lpcap

main.o :
	g++ -g -c -o main.o main.cpp

PRINT.o :
	g++ -g -c -o PRINT.o PRINT.cpp

clean :
	rm -f pcap_hello
	rm -f *.o
