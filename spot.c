#include<pcap.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include<sys/socket.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
#include<netinet/ip.h> 

/* ------ CONSTANTS ------ */
int ERRBUFF_SIZE = 100;


/* ------ GENERAL VARS ------ */
FILE *f;




//TODO: Add prototypes, I don't wanna make main.h

int main(int argc, char *argv[]){

	printf("Hello, are you here to look at some packets? \n");

	char *deviceName, errbuf[ERRBUFF_SIZE];
	pcap_t *handler; //dev handler

	if (argc > 2){
		printf("Too many arguments! You can either give me the name of the device you want to snoop or leave it empty so I can find ones. \n");
		return -1;
	}

	if (argc == 2){
		printf("I detect a device, lemme snoop... \n");

		deviceName = argv[1];

		//verify that the input is a given device 

		printf("Device: %s\n", deviceName);

		
	} else {
		//All available devices
		printf("Searching for available devices to snoop... \n");

		pcap_if_t *allDevices, *device;

		int deviceCount = 0;
		char devs[100][100];

		//Can't find any devices
		if (pcap_findalldevs(&allDevices, errbuf) < 0){
			printf("Couldn't find any available devices! \n");
			printf("Here's some error code: %s", errbuf);
			exit(1);
			}

		//List devices
		for(device = allDevices; device != NULL; device = device->next){
			deviceCount++;
			printf("%d. %s", deviceCount, device->name);
			strcpy(devs[deviceCount], device->name);

			//Check if the given device has a description attached to it
			if (device->description)
				printf(" (%s)\n", device->description);
			else
				printf(" (No description available for this device)\n");
			}

		if (deviceCount == 0){
			printf("\nNo interfaces found! \n");
			return -1;
			}

		//Find a device to sniff
		int n;
		printf("Enter the number of the device you want to sniff : ");
		scanf("%d" , &n);
		deviceName = devs[n];

		//At this point we don't need the allDevices list anymore so free it
		pcap_freealldevs(allDevices);
		}


	//Open the device to sniff
	printf("Opening now... \n");
	
	if ((handler = pcap_open_live(deviceName, 1000, 1, 0, errbuf)) == NULL){
		printf("Something happened and I couldn't open the device :( \n");
		exit(2);
	}

	//Do some file stuff...

	//Process the packet recieved - user callback function

}
