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

void analyze_packet(u_char *handler, const struct pcap_pkthdr *pktHeader, const u_char *pkt);
void print_ip(const u_char *buf, int size);


/* ------ CONSTANTS ------ */
int ERRBUFF_SIZE = 100;


/* ------ GENERAL VARS ------ */
FILE *f;

struct sockaddr_in source,dest;

/*
   / \__
  (    @\___
  /         O
 /   (_____/
/_____/   U Wooof 
*/


int main(int argc, char *argv[]){


	printf("Woof! \n");


	char *deviceName, errbuf[ERRBUFF_SIZE];
	pcap_t *handler; //dev handler
	int ans; //for user input

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
		printf("============\n");
		printf("\n");

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
		printf("Enter the number of the device you want to sniff : ");
		scanf("%d" , &ans);
		//At this point we don't need the allDevices list anymore so free it
		pcap_freealldevs(allDevices);
	}



	printf("Opening %s now! \n", deviceName);
	printf("============\n");
	printf("\n");



	handler = pcap_open_live(deviceName, 655336, 1, 0, errbuf);
	
	if (handler == NULL){
		printf("Something happened and I couldn't open the device :( \n");
		printf("%s", errbuf);
		exit(2);
	}


	printf("Would you like to create a text doc and log packet information into it? \n");
	printf("\n1. No\n");
	printf("\n2. Yes\n");
	scanf("%d", &ans);

	if (ans == 2){
		printf("\n ");
		printf("Creating the log file now...\n");
		f = fopen("log.txt", "w");

		if (f == NULL){
			printf("Error creating the log text doc. \n");
			exit(1);
		}
	}



	//Ask if user wants to apply filters, then do so
	printf("Currently, %s is on promisc mode by default. Did you want to apply filters?\n", deviceName);
	printf("\n1. No\n");
	printf("\n2. Yes\n");

	scanf("%d", &ans);

	struct bpf_program fp;	
	char *filter_exp;	
	bpf_u_int32 mask;		
	bpf_u_int32 net;	

	switch(ans){
		case 1:  
		printf("No problem, moving forward! \n");
		break;
		case 2:
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
		default:
		printf("Couldn't read your input. NO filters applied. \n");
		break;
	}



	printf("How many packets do you want me to grab? (0 to grab packets continously, until an err occurs.) \n");
	scanf("%d", &ans);

	if(ans < 0){
		printf("Invalid input. \n");
		//return...?
	}

	if (ans == 0){
		pcap_loop(handler, -1, analyze_packet, NULL);
	} else {
		printf("I will sniff [%d] packets.\n", ans);
		pcap_loop(handler, ans, analyze_packet, NULL);

	}

	while (1){
		printf("WOuld you like to scan more packets? \n");
		printf("\n1. No\n");
		printf("\n2. Yes\n");
		scanf("%d", &ans);

		if (ans == 1){
			printf("Woof! \n");
			return 0;
		} else if (ans == 2){
			printf("How many packets? \n");
			int temp;
			scanf("%d", &temp);
			if (temp == 0){
				pcap_loop(handler, -1, analyze_packet, NULL);
			} else {
				printf("I will sniff [%d] packets.\n", temp);
				pcap_loop(handler, temp, analyze_packet, NULL);
			}
		}
	}
	return 0;
}



void analyze_packet(u_char *handler, const struct pcap_pkthdr *pktHeader, const u_char *pkt){
	int size = pktHeader->len;

    //Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *ip = (struct iphdr*)(pkt + sizeof(struct ethhdr));

	unsigned short iphdrlen;

	//STEP 1: Print the IP header
	print_ip(pkt, size);

	//STEP 2: Print specific protocol header
	int protocol = ip->protocol;
	switch(protocol){
		case 6: //TCP


		iphdrlen = ip->ihl*4;

		struct tcphdr *tcph=(struct tcphdr*)(pkt + iphdrlen + sizeof(struct ethhdr));

		int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;


		if (f){
		fprintf(f , "\n\n***********************TCP Packet*************************\n");  

		fprintf(f , "\n");
		fprintf(f , "TCP Header\n");
		fprintf(f , "   |-Source Port      : %u\n",ntohs(tcph->source));
		fprintf(f , "   |-Destination Port : %u\n",ntohs(tcph->dest));
		fprintf(f , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
		fprintf(f , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
		fprintf(f , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
		fprintf(f , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
		fprintf(f , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
		fprintf(f , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
		fprintf(f , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
		fprintf(f , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
		fprintf(f , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
		fprintf(f , "   |-Window         : %d\n",ntohs(tcph->window));
		fprintf(f , "   |-Checksum       : %d\n",ntohs(tcph->check));
		fprintf(f , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
		fprintf(f , "\n");
		fprintf(f , "                        DATA Dump                         ");
		fprintf(f , "\n");

		fprintf(f , "\n###########################################################");
		}


		printf("\n\n***********************TCP Packet*************************\n");  

		printf("\n");
		printf("TCP Header\n");
		printf("   |-Source Port      : %u\n",ntohs(tcph->source));
		printf("   |-Destination Port : %u\n",ntohs(tcph->dest));
		printf("   |-Sequence Number    : %u\n",ntohl(tcph->seq));
		printf("   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
		printf("   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
		printf("   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
		printf("   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
		printf("   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
		printf("   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
		printf("   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
		printf("   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
		printf("   |-Window         : %d\n",ntohs(tcph->window));
		printf("   |-Checksum       : %d\n",ntohs(tcph->check));
		printf("   |-Urgent Pointer : %d\n",tcph->urg_ptr);
		printf("\n");
		printf("                        DATA Dump                         ");
		printf("\n");

		printf("\n###########################################################");

		break;




		default:

		break;
	}
}

void print_ip(const u_char *buf, int size){

	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)(buf  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	if (f){
		fprintf(f , "\n");
		fprintf(f , "IP Header\n");
		fprintf(f , "   |-IP Version        : %d\n",(unsigned int)iph->version);
		fprintf(f , "   |-Supplementary Protocol 	: %d\n", (unsigned int)iph->protocol);
		fprintf(f , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
		fprintf(f , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
		fprintf(f , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
		fprintf(f , "   |-Identification    : %d\n",ntohs(iph->id));
		fprintf(f , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
		fprintf(f , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
		fprintf(f , "   |-Checksum : %d\n",ntohs(iph->check));
		fprintf(f , "   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr));
		fprintf(f,  "   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
		printf("Analyzed and put packet contents in log.txt :)\n");		
	}

	printf("\n");
	printf("IP Header\n");
	printf("   |-IP Version       : %d\n",(unsigned int)iph->version);
	printf("   |-IP Header Length : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	printf("   |-Type Of Service  : %d\n",(unsigned int)iph->tos);
	printf("   |-IP Total Length  : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	printf("   |-Identification   : %d\n",ntohs(iph->id));
	printf("   |-TTL      		  : %d\n",(unsigned int)iph->ttl);
	printf("   |-Protocol 		  : %d\n",(unsigned int)iph->protocol);
	printf("   |-Checksum 		  : %d\n",ntohs(iph->check));
	printf("   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr));
	printf("   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
/*

	FILE *temp;
	char c;

	temp = fopen("log.txt", "r");


	c = fgetc(temp);
	printf ("%c", c); 

	fclose(temp);

*/

}
