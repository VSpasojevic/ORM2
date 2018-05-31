// ================================================================
// Katedra: Katedra za racunarsku tehniku i racunarske komunikacije
// Predmet: Osnovi racunarskih mreza 2
// Godina studija: III godina
// Semestar: Letnji (VI)
// Studinti: 
// Skolska godina: 2017/2018
// Datoteka: Multipath UDP
// ================================================================


// Include libraries
// We do not want the warnings about the old deprecated and unsecure CRT functions since these examples can be compiled under *nix as well
#ifdef _MSC_VER
	#define _CRT_SECURE_NO_WARNINGS
#else
#include <netinet/in.h>
#include <time.h>
#endif

#include <pcap.h>
#include <pthread.h>
#include <string.h>
#include "protocol_headers.h"
#include <unistd.h> // sleep


#define SLEEP_TIME 5

typedef enum {false, true} bool;

pthread_mutex_t mutex;

unsigned char test_data[100];

#define	ETHERTYPE_ARP		0x0806		/* Address resolution */

void packet_handler(unsigned char* user,  struct pcap_pkthdr* packet_header,  unsigned char* packet_data);

pcap_t* device_handle_in, *device_handle_wifi;
pcap_t* device_handle_in, *device_handle_eth;

void eth_fill_eth_h(ethernet_header *eh);
void eth_fill_ip_h(ip_header *ih);
void eth_fill_udp_h(udp_header *uh);

void wifi_fill_eth_h(ethernet_header *eh);
void wifi_fill_ip_h(ip_header *ih);
void wifi_fill_udp_h(udp_header *uh);


void* sendData(void* arg);
bool deviceAvailable(char *dev_name);

int main()
{

    int i=0;
    int device_number;

	pcap_if_t* devices;
	pcap_if_t* device;
	pcap_if_t* device1;
	pcap_if_t* device2;
	char error_buffer [PCAP_ERRBUF_SIZE];
	
	ethernet_header eh_eth, eh_wifi;
	ip_header ih_eth, ih_wifi;
	udp_header uh_eth, uh_wifi ;
	
	
	/**************************************************************/
	//Retrieve the device list on the local machine 
	if (pcap_findalldevs(&devices, error_buffer) == -1)
	{
		printf("Error in pcap_findalldevs: %s\n", error_buffer);
		return -1;
	}
	// Count devices and provide jumping to the selected device 
	// Print the list
	for(device=devices; device; device=device->next)
	{
	
		printf("%d. %s", ++i, device->name);
		if (device->description)
			printf(" (%s)\n", device->description);
		else
			printf(" (No description available)\n");
			
		// get eth0 and wlan0
		// device1 for eth and device2 for wifi
		if (strcmp(device->name, "eth0") == 0) {

			device1 = device;
			printf("\nTT11 %s\n", device1->name);
		}
		if (strcmp(device->name, "wlan0") == 0 || strcmp(device->name, "wlan1") == 0) {
			
			device2 = device;
		}	
		
	}

	if (strcmp(device1->name, "") == 0 /*|| strcmp(device2->name, "") == 0 */) {
		printf("Device not found.\n");
		return -1;
	}

	//printf("\nSending on: %s, %s\n", device1->name, device2->name);
	printf("\nSending on: %s\n", device1->name);


	// Check if list is empty
	if (i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	
	// fill ethernet header, ip header, udp header
	eth_fill_eth_h(&eh_eth);
	eth_fill_ip_h(&ih_eth);
	eth_fill_udp_h(&uh_eth);
	
	
	//fill wifi header , ip header, udp header
	
/*	
	wifi_fill_eth_h(&eh_wifi);	
	wifi_fill_ih_h(&ih_wifi);	
	wifi_fill_uh_h(&uh_wifi);	
*/	
	/*
	printf("%d\n", eh_eth.dest_address[0]);
	printf("%d\n", ih_eth.src_addr[0]);
	*/
	
	memcpy(test_data, &eh_eth, 14);
	memcpy(test_data + 14, &ih_eth, 20);
	memcpy(test_data + 34, &uh_eth, 8);
	
	// "This is my data"
	test_data[43] = 'T';
	test_data[44] = 'h';
	test_data[45] = 'i';
	test_data[46] = 's';
	test_data[47] = ' ';
	test_data[48] = 'i';
	test_data[49] = 's';
	test_data[50] = ' ';
	test_data[51] = 'm';
	test_data[52] = 'y';
	test_data[53] = ' ';
	test_data[54] = 'd';
	test_data[55] = 'a';
	test_data[56] = 't';
	test_data[57] = 'a';
	test_data[58] = '\0';
	
	//strcpy(test_data+43, "This is my data\0");
	
	/**************************************************************/
	
	// Open the output adapter (FOR ETH)
	if ((device_handle_eth  = pcap_open_live(device1->name, 100, 1, 2000, error_buffer)) == NULL)
	{
		printf("\n Unable to open adapter %s.\n", device1->name);
		return -1;
	}

	// Open the output adapter (FOR WIFI)
//	if ((device_handle_wifi = pcap_open_live(device2->name, 100, 1, 2000, error_buffer)) == NULL)
//	{
//		printf("\n Unable to open adapter %s.\n", device2->name);
//		return -1;
//	}

	// creating threads and sending data
	pthread_t eth_thr;
//	pthread_t wifi_thr;
	
	if (pthread_create(&eth_thr, NULL, sendData, (void*)device1) != 0) {
		printf("Error creating thread eth");
	}
//	if (pthread_create(&wifi_thr, NULL, sendData, (void*)device2) != 0) {
//		printf("Error creating thread wifi");
//	}


	pthread_join(eth_thr, NULL);
//	pthread_join(wifi_thr, NULL);


	// !!! IMPORTANT: remember to close the output adapter,
	// otherwise there will be no guarantee that all the packets will be sent!
	pcap_close(device_handle_wifi);
	pcap_close(device_handle_eth);

	return 0;
}

void* sendData(void* arg)
{
	pcap_if_t* device = (pcap_if_t*) arg;	
	pcap_t *device_handle;
	char error_buffer[PCAP_ERRBUF_SIZE];
	unsigned char packet[100];

	printf("\nSending on device: %s\n", device->name);	
	
	// if device is alive send data over it , if not sleep
	// close the device?
	if ((device_handle = pcap_open_live( device->name, // name of the device
								100, // portion of the packet
								1, //promiscuous mode
								2000, // read timeout
								error_buffer // error message
	   )) == NULL) 
	{
		printf("\nUnable to open the adapter. %s is not supported by LibPcap\n",
			  device->name);
		sleep(SLEEP_TIME);
	}

	int i;
	for(i = 0; i < 10; i++) {
		printf("\nSending on device: %s\n", device->name);
	}



		if (pcap_sendpacket(device_handle, test_data, 60) != 0) {
		
			printf("Error sending the packet: %s\n", pcap_geterr(device_handle));
		}
	
}


void eth_fill_eth_h(ethernet_header *eh)
{

	eh->dest_address[0] = 0x2c;			// Destination address
	eh->dest_address[1] = 0x4d;
	eh->dest_address[2] = 0x54;
	eh->dest_address[3] = 0x56;
	eh->dest_address[4] = 0x99;
	eh->dest_address[5] = 0x14;
	
	eh->src_address[0] = 0xb8;			// Source address
	eh->src_address[1] = 0x27;
	eh->src_address[2] = 0xeb;
	eh->src_address[3] = 0xd5;
	eh->src_address[4] = 0xe1;
	eh->src_address[5] = 0xcd;
	
	eh->type = htons(0x0800);  // TYPE IP			// Type of the next layer

}

void eth_fill_ip_h(ip_header *ih)
{

	ih->header_length = 5;	// 20 mozda					// Internet header length (4 bits)
	ih->version = 4;									// Version (4 bits)
	ih->tos = 0x00;										// Type of service // ECN
	ih->length = htons(44);	// this is my data packet	// Total length 
	ih->identification = htons(0xed37);					// Identification
	ih->fragm_flags = htons(0x02); 						// Flags (3 bits) & Fragment offset (13 bits)	
	ih->fragm_offset = htons(0);						// Flags (3 bits) & Fragment offset (13 bits)
	ih->ttl = 64;										// Time to live
	ih->next_protocol = 0x11; 	// UDP					// Protocol of the next layer
	ih->checksum = htons(0xfa85);						// Header checksum
	ih->src_addr[0] = 10;								// Source address
	ih->src_addr[1] = 81;
	ih->src_addr[2] = 31;
	ih->src_addr[3] = 41;
	
	ih->dst_addr[0] = 10;								// Destination address
	ih->dst_addr[1] = 81;
	ih->dst_addr[2] = 31;
	ih->dst_addr[3] = 57;
	
//  ih->options_padding = ;									// Option + Padding

//htons
//ntos
}

void eth_fill_udp_h(udp_header *uh)
{

	uh->src_port = 60052;			// Source port
	uh->dest_port = 4000;			// Destination port
	uh->datagram_length = 24;		// Length of datagram including UDP header and data
	uh->checksum = 0x1456;			// Header checksum

}








/*
pthread_mutex_lock(&mutex);

pthread_mutex_unlock(&mutex);

*/






