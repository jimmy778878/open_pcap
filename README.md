compile : gcc open_pcap.c -o open_pcap -lpcap

run : ./open_pcap -r [pcap file]
