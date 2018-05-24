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


pthread_mutex_t mutex;

int test_data;

#define	ETHERTYPE_ARP		0x0806		/* Address resolution */

void packet_handler(unsigned char* user,  struct pcap_pkthdr* packet_header,  unsigned char* packet_data);

pcap_t* device_handle_in, *device_handle_wifi;
pcap_t* device_handle_in, *device_handle_eth;

unsigned char packet[100];

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
		if (strcmp(device->name, "eth0") == 0) {

			device1 = device;
			printf("\n%s\n", device1->name);
		}
		if (strcmp(device->name, "wlan0") == 0 || strcmp(device->name, "wlan1") == 0) {
			
			device2 = device;
		}	
		
	}

	if (strcmp(device1->name, "") == 0 || strcmp(device2->name, "") == 0 ) {
		printf("Device not found.");
		return -1;
	}

	printf("\nSending on: %s, %s\n", device1->name, device2->name);

	// Check if list is empty
	if (i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	/**************************************************************/
	
	// Open the output adapter (FOR WIFI)
	if ((device_handle_wifi = pcap_open_live(device1->name, 100, 1, 2000, error_buffer)) == NULL)
	{
		printf("\n Unable to open adapter %s.\n", device1->name);
		return -1;
	}

	// Open the output adapter (FOR ETH)
	if ((device_handle_eth = pcap_open_live(device2->name, 100, 1, 2000, error_buffer)) == NULL)
	{
		printf("\n Unable to open adapter %s.\n", device2->name);
		return -1;
	}

	// creating threads and sending data
	pthread_t eth_thr;
	pthread_t wifi_thr;
	
	if (pthread_create(&eth_thr, NULL, sendData, (void*)device1->name) != 0) {
		printf("Error creating thread eth");
	}
	if (pthread_create(&wifi_thr, NULL, sendData, (void*)device2->name) != 0) {
		printf("Error creating thread wifi");
	}






	pthread_join(eth_thr, NULL);
	pthread_join(wifi_thr, NULL);


	// !!! IMPORTANT: remember to close the output adapter, otherwise there will be no guarantee that all the packets will be sent!
	pcap_close(device_handle_wifi);
	pcap_close(device_handle_eth);

	return 0;
}

void* sendData(void* arg)
{
	
	char *str = (char*) arg;
	printf("\nSending on device: %s\n", str);

	int i;
	for(i = 0; i < 100; i++) {
		printf("\nSending on device: %s\n", str);
		test_data++;
	}


}


bool deviceAvailable(char *dev_name)
{



}


/*
pthread_mutex_lock(&mutex);

pthread_mutex_unlock(&mutex);

*/






