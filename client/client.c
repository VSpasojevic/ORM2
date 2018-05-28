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
	for(i = 0; i < 100; i++) {
		printf("\nSending on device: %s\n", device->name);
	}

	
	// napravi udp pakete i salji
	
	// Supposing to be on Ethernet, set MAC destination address
/*		test_data[0] = 0x38;
		test_data[1] = 0xd5;
		test_data[2] = 0x47;
		test_data[3] = 0xde;
		test_data[4] = 0xed;
		test_data[5] = 0x05;
		
		
	//  Set MAC source address 
		test_data[6] = 0x38;
		test_data[7] = 0xd5;
		test_data[8] = 0x47;
		test_data[9] = 0xde;
		test_data[10] = 0xeb;
		test_data[11] = 0xd2;*/
		
		for(i = 12; i < 100; i++) {
			test_data[i] = (unsigned char)i;
		}

		if (pcap_sendpacket(device_handle, test_data, 100) != 0) {
		
			printf("Error sending the packet: %s\n", pcap_geterr(device_handle));
		}
	


}



/*
pthread_mutex_lock(&mutex);

pthread_mutex_unlock(&mutex);

*/






