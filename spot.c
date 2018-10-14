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

	printf("Woof! \n");

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
		printf("SInce a device wasn't specified, I am gonna start snooping for some... \n");
		printf("\n ******************** \n");

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
			printf("%d. || %s", deviceCount, device->name);
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

	
	handler = pcap_open_live(deviceName, 650536, 1, 0, errbuf);
	
	if (handler == NULL){
		printf("Something happened and I couldn't open the device :( \n");
		printf("%s", errbuf);
		exit(2);
	}

	

	//Ask if user wants to apply filters, then do so
	printf("Currently, %s is on promisc mode by default. Did you want to apply filters?\n", deviceName);
	printf("1 for yes / 2 for no : ");

	int ans;
	scanf("%d", &ans);

	struct bpf_program fp;		/* The compiled filter */
	char *filter_exp;	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;	

	switch(ans){
		case 1:  
		printf("Please specify the filter expression you want to apply. \n");
		scanf("%s", filter_exp);
		if (pcap_compile(handler, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handler));
			return(2);
		}
		if (pcap_setfilter(handler, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handler));
			return(2);
		}
		printf("Applied filter: %s", filter_exp);
		break;
		case 2: 
		printf("No problem, moving forward! \n");
		break;
		default:
		printf("Couldn't read your input. NO filters applied. \n");
		break;
	}

	printf("right now I would be processing some packets rn but atm this is not implemented. \n");
	return 0;
	//Process the packet recieved - user callback function

}
