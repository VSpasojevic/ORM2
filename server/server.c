// ================================================================
// Katedra: Katedra za racunarsku tehniku i racunarske komunikacije
// Predmet: Osnovi racunarskih mreza 2
// Godina studija: III godina
// Semestar: Letnji (VI)
// Studinti: 
// Skolska godina: 2017/2018
// Datoteka: Multipath UDP
// ================================================================


/ Include libraries
// We do not want the warnings about the old deprecated and unsecure CRT functions since these examples can be compiled under *nix as well
#ifdef _MSC_VER
	#define _CRT_SECURE_NO_WARNINGS
#else
#include <netinet/in.h>
#include <time.h>
#endif

#include "pcap.h"
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#define	ETHERTYPE_ARP		0x0806		/* Address resolution */

void packet_handler(unsigned char* user,  struct pcap_pkthdr* packet_header,  unsigned char* packet_data);

pcap_t* device_handle_in, *device_handle_wifi;
pcap_t* device_handle_in, *device_handle_eth;

unsigned char packet[100];

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
	}

	// Check if list is empty
	if (i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	// Pick FIRST device from the list
	printf("Enter the output interface number (1-%d):",i);
	scanf("%d", &device_number);

	if(device_number < 1 || device_number > i)
	{
		printf("\nInterface number out of range.\n");
		return -1;
	}

	// Select the first device...
	device1=devices;
	// ...and then jump to chosen devices
	for (i=0; i<device_number-1; i++)
	{
		device1=device1->next;
	}
	
	// Pick SECOND device from the list
	printf("Enter the output interface number (1-%d):",i);
	scanf("%d", &device_number);

	if(device_number < 1 || device_number > i)
	{
		printf("\nInterface number out of range.\n");
		return -1;
	}

	// Select the second device...
	device2=devices;
	// ...and then jump to chosen devices
	for (i=0; i<device_number-1; i++)
	{
		device2=device2->next;
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

















	// !!! IMPORTANT: remember to close the output adapter, otherwise there will be no guarantee that all the packets will be sent!
	pcap_close(device_handle_wifi);
	pcap_close(device_handle_eth);

	return 0;
}



