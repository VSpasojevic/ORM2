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

void fill_eth_h(ethernet_header *eh);
void fill_ip_h(ip_header *ih);
void fill_udp_h(udp_header *uh);


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
	
	ethernet_header eh;
	ip_header ih;
	udp_header uh;
	
	
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
	fill_eth_h(&eh);
	//fill_ip_h(&ih);
	//fill_udp_h(&uh);
	
	printf("%d", eh.dest_address[0]);
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

	
	// napravi udp pakete i salji

		
		for(i = 0; i < 20; i++) {
			test_data[i] = (unsigned char)i;
		}

		if (pcap_sendpacket(device_handle, test_data, 100) != 0) {
		
			printf("Error sending the packet: %s\n", pcap_geterr(device_handle));
		}
	
}


void fill_eth_h(ethernet_header *eh)
{
/*	unsigned char dest_address[6];		// Destination address
	unsigned char src_address[6];		// Source address
	unsigned short type;				// Type of the next layer
*/

	eh->dest_address[0] = 0x2c;
	eh->dest_address[1] = 0x4d;
	eh->dest_address[2] = 0x54;
	eh->dest_address[3] = 0x56;
	eh->dest_address[4] = 0x99;
	eh->dest_address[5] = 0x14;
	
	eh->src_address[0] = 0xb8;
	eh->src_address[1] = 0x27;
	eh->src_address[2] = 0xeb;
	eh->src_address[3] = 0xd5;
	eh->src_address[4] = 0xe1;
	eh->src_address[5] = 0xcd;
	
	eh->type = 0x800;  // TYPE IP

}

void fill_ip_h(ip_header *ih)
{
/*	unsigned char header_length :4;	// Internet header length (4 bits)
	unsigned char version :4;		// Version (4 bits)
	unsigned char tos;				// Type of service 
	unsigned short length;			// Total length 
	unsigned short identification;	// Identification
	unsigned short fragm_flags :3;  // Flags (3 bits) & Fragment offset (13 bits)
    unsigned short fragm_offset :13;// Flags (3 bits) & Fragment offset (13 bits)
	unsigned char ttl;				// Time to live
	unsigned char next_protocol;	// Protocol of the next layer
	unsigned short checksum;		// Header checksum
	unsigned char src_addr[4];		// Source address
	unsigned char dst_addr[4];		// Destination address
	unsigned int options_padding;	// Option + Padding
		// + variable part of the header
*/

	ih->header_length = ;
	ih->version = ;
	ih->tos = ;
	ih->length = ;
	ih->identification = ;
	ih->fragm_flags = 0x02; //(don't fragment 0x02)
	ih->fragm_offset = 0;
	ih->ttl = 64;
	ih->next_protocol = ;
	ih->checksum = ;
	ih->src_addr[0] = ;
	ih->src_addr[0] = ;
	ih->src_addr[0] = ;
	ih->src_addr[0] = ;
	
	ih->dst_addr[0] = ;
	ih->dst_addr[0] = ;
	ih->dst_addr[0] = ;
	ih->dst_addr[0] = ;
	
	ih->options_padding = ;

//htons
//ntos
}

void fill_udp_h(udp_header *uh)
{
/*	unsigned short src_port;		// Source port
	unsigned short dest_port;		// Destination port
	unsigned short datagram_length;	// Length of datagram including UDP header and data
	unsigned short checksum;		// Header checksum
*/

	uh->src_port = 59138;
	uh->dest_prot = 4000;
	uh->datagram_length = 24;
	uh->checksum = 0x1456;

}


/*
pthread_mutex_lock(&mutex);

pthread_mutex_unlock(&mutex);

*/






