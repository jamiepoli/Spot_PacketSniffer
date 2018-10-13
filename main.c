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

int ERRBUFF_SIZE = 100;


//test


//TODO: Add prototypes, I don't wanna make main.h

int main(int argc, char *argv[]){

	printf("Hello, are you here to look at some packets? \n");

	char *devname;

	if (argv){
		printf("You gave me a device already, lemme snoop... \n");

		devname = argv[1];

		//verify that the input is a given device 

		printf("Device: %s\n", dev);

		
	} else {
		//All available devices
		printf("Searching for available devices to snoop... \n");

		pcap_if_t *allDevices, *device;
		pcap_t *handler; //dev handler
		int i = 0;
		char devs[100][100], errbuf[ERRBUFF_SIZE];

		//Can't find any devices
		if (pcap_findalldevs(&allDevices, errbuf) < 0){
			printf("Couldn't find any available devices! \n");
			printf("Here's some error code: %s", errbuf);
			exit(1);
			}

		//List devices
		for(device = allDevices; device != NULL; device = device->next){
			printf("%d. %s", i++, device->name);
			if (device->description)
				printf(" (%s)\n", device->description);
			else
				printf(" (No description available for this device)\n");
			}

		if (i == 0){
			printf("\nNo interfaces found! \n");
			return;
			}

		//Find a device to sniff
		printf("Enter the number of the device you want to sniff : ");
		scanf("%d" , &n);
		devname = devs[n];

		}

	//Open the device to sniff
	printf("Opening now... \n");
	//pcap open device? 

	//Process the packet recieved - user callback function

}
