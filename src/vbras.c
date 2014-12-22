#include "headers.h"
#include "variables.h"
#include "functions_general.h"
#include "functions_pppoe.h"
#include "functions_lcp.h"
#include "functions_ppp.h"
#include "functions_ipcp.h"
#include "functions_ipv6cp.h"
#include "functions_tree.h"
#include "functions_thread.h"

// Declaration of thread for listening of incoming packets and the structure for passing thread arguments
void *ParseIncomingPackets(void *args);
typedef struct {
	unsigned long mac;
        int rawSocket;
} THREAD_ARGS;

// Main thread in the program
int main(int argc, char **argv)
{
	int i, j, tmp, rawSocket, ipSocket, bytesReceived;
	BYTE packet[PACKET_LENGTH], packet_ip[PACKET_LENGTH];
	ETHERTYPE ethtype;
	MAC_ADDRESS sourceMAC;
	PPP_PROTOCOL pppProto;
	RESPONSE response, response_additional;
	struct sockaddr_in sin;
	struct ifreq if_mac;
        BYTE *mac;
	unsigned long subscriberMAC;
	SUBSCRIBER *sub;
	FILE *fd;
	pthread_t internetPackets, tmpThread;
	THREAD_ARGS threadArgs;

	sub = malloc(sizeof(SUBSCRIBER));

	// The list of subscribers is empty at the beginning
	subscriberList = NULL;

	// Read configuration file
	if (argc < 2) fd = fopen("vbras.conf", "r");
        else if (argc == 2) fd = fopen(argv[1], "r");
        else {
                perror("Usage: sudo ./vbras [CONFIGURATION_FILE]\n");
                return -1;
        }
	if (fd == NULL) {
		perror("Configuration file not found");
		return -1;
	}
	SetExternVariables(fd);

	// Create and bind a raw socket to the subscriber-facing interface
	if ((rawSocket = BindRawSocket(subscriberInterface)) == -1) return -1;
	
	// Create socket for outgoing IP packets
	if ((ipSocket = CreateIPSocket()) == -1) return -1;
	memset (&sin, 0, sizeof (struct sockaddr_in));
        sin.sin_family = AF_INET;

	// Get the MAC address of subscriber-facing interface
	if ((mac = GetMACAddress(subscriberInterface, rawSocket)) == NULL) return -1;

	// Start thread for listening packets from the Internet-facing interface
	threadArgs.rawSocket = rawSocket;
        if (pthread_create(&internetPackets, NULL, ParseIncomingPackets, &threadArgs)) {
                perror("Listening thread not created");
                return -1;
        }

	// Initiate semaphores
	sem_init(&semaphoreTree, 0, 1);

        printf("\nvbras: Slusam na %s i cekam PPPoE pakete\n", subscriberInterface);

	// Listen to all incoming packets
	while(1) {

		bytesReceived = recvfrom(rawSocket, &packet, PACKET_LENGTH, 0, NULL, NULL);
		if (bytesReceived == -1) {
			perror("No packets received");
			return -1;
		}

		// Find relevant fields for if-else tree, the packet ethernet type and ppp protocol
		ethtype = packet[12] * 256 + packet[13];
		
		// Discard packets with non-relevant ethtypes
		if ( (!(ethtype ^ ETH_P_PPP_SES)) & (!(ethtype ^ ETH_P_PPP_DISC)) ) continue;

		pppProto = packet[20] * 256 + packet[21];

		//TODO IPv6, izbaceno je "| (!(pppProto ^ 0x0057)" iz IF-a ispod

		// If incoming packet is regular PPPoE traffic, verify the source MAC address and forward
		// Regular PPPoE traffic == ethernet type 0x8864 and PPP protocol type IPv4 or IPv6
		if ( (!(ethtype ^ ETH_P_PPP_SES)) & (!(pppProto ^ 0x0021)) ) {
			
			sourceMAC[0] = packet[6] + packet[7] * 256;
			sourceMAC[1] = packet[8] + packet[9] * 256;
			sourceMAC[2] = packet[10] + packet[11] * 256;
			subscriberMAC = ((unsigned long) ntohs(sourceMAC[0]) << 32) | ((unsigned long) ntohs(sourceMAC[1]) << 16) | ((unsigned long) ntohs(sourceMAC[2]));
			
			// If the source MAC address doesn't belong to a registered subscriber, discard the packet implicitly
			sub = NULL;
			sem_wait(&semaphoreTree);
			sub = FindSubscriberMAC(&subscriberList, subscriberMAC);
			sem_post(&semaphoreTree);
			if (sub == NULL) continue;

                        // Remove Ethernet, PPPoE and PPP headers
			tmp = bytesReceived - ETH_HEADER_LENGTH - PPPoE_HEADER_LENGTH - PPP_HEADER_LENGTH;
                        for (i = 0; i < tmp; i++)
                                packet_ip[i] = packet[i + ETH_HEADER_LENGTH + PPPoE_HEADER_LENGTH + PPP_HEADER_LENGTH];

			// Send packet to the destination IP address, i.e. towards the Internet	
			//sin.sin_addr.s_addr = packet_ip[16] * 16777216 + packet_ip[17] * 65536 + packet_ip[18] * 256 + packet_ip[19];
			sin.sin_addr.s_addr = (packet_ip[16] << 24) | (packet_ip[17] << 16) | (packet_ip[18] << 8) | packet_ip[19];
			if (sendto(ipSocket, packet_ip, tmp - 4, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0)  {
    				perror("vbras: IP packet sending failed");
    				continue;
  			}

			continue;
		}

		//TODO maknuti ovo ispod kad bude IPv6 implementirano
		else if ( (!(ethtype ^ ETH_P_PPP_SES)) & (!(pppProto ^ 0x0057)) ) continue;
		//TODO maknuti ovo iznad

		// If the ethertype is PPPoE, but not regular traffic, parse on the control plane
		// Parse control plane packets with Discover Ethertype
		else if (!(ethtype ^ ETH_P_PPP_DISC)) {
                        
			// Parse Discover packet
                        response = ParseIncoming_Discover(packet, bytesReceived);
                        if (response.length == 0) continue;                     
                        
                        // Set source MAC address (subscriber-facing interface)
                        for (i = 6, j = 0; i < 12; i++, j++) {
                                response.packet[i] = mac[j];            
                        }
                
			// Send response to Discover
                        if ((sendto(rawSocket, response.packet, response.length, 0, NULL, sizeof(struct sockaddr_ll))) == -1) {
                                perror("Raw Send error - Discover response");
                                return -1;
                        }

                        continue; 
                }

		// Parse control plane packets with Session Ethertype
		else if (!(ethtype ^ ETH_P_PPP_SES)) {
                        
                        response = ParseIncoming_Session(packet, bytesReceived);
                        if (response.length == 0) continue;             

                        //TODO brojevi bajtova ne smiju biti hardkodirani ovo u if uvjetu !!!!!!
                        // If Configuration-Ack has been sent, send Configuration request
                        if ( (response.packet[20] == 0xc0) && (response.packet[21] == 0x21) && (response.packet[22] == 0x02) ) {
                                
				response_additional = SendConfigureRequest(response);
                                        
                                // Set source MAC address (subscriber-facing interface)
                                for (i = 6, j = 0; i < 12; i++, j++) {
                                        response_additional.packet[i] = mac[j];            
                                }
                                if ((sendto(rawSocket, response_additional.packet, response_additional.length, 0, NULL, sizeof(struct sockaddr_ll))) == -1) {
                                        perror("Raw Send error - Session response");
                                        return -1;
                                } 
                        }
			// If IPCP Ack has been sent, send IPCP ConfigurationRequest and start new customer thread
                        if ( (response.packet[20] == 0x80) && (response.packet[21] == 0x21) && (response.packet[22] == 0x02) ) {
                                	
				response_additional = SendIPCPConfigureRequest(response);
                                        
                                // Set source MAC address (subscriber-facing interface)
                                for (i = 6, j = 0; i < 12; i++, j++) {
                                	response_additional.packet[i] = mac[j];            
                                }
                                if ((sendto(rawSocket, response_additional.packet, response_additional.length, 0, NULL, sizeof(struct sockaddr_ll))) == -1) {
                                	perror("Raw Send error - Session response");
                                        return -1;
                                }

				// Start customer thread
				memset(&threadArgs, 0, sizeof(THREAD_ARGS));
				threadArgs.mac = ((unsigned long)response.packet[0] << 40) | ((unsigned long)response.packet[1] << 32) | ((unsigned long)response.packet[2] << 24) | ((unsigned long)response.packet[3] << 16) | ((unsigned long)response.packet[4] << 8) | (unsigned long)response.packet[5];
        			threadArgs.rawSocket = rawSocket;
        			
				printf("vbras: mac adresa korisnika cija se dretva pokrece je %lu\n", threadArgs.mac);
				//printf("vbras: mac segmenti su 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n", response.packet[5], response.packet[4], response.packet[3], response.packet[2], response.packet[1], response.packet[0]);

				if (pthread_create(&tmpThread, NULL, SubscriberLCPEchoThread, &threadArgs)) {
                			perror("Subscriber thread not created");
                			return -1;
        			}
				//sem_wait(&semaphoreTree);
				//SetSubscriberThreadID(&subscriberList, threadArgs.mac, *tmpThread);
				//sem_post(&semaphoreTree);
                        }       
			// If IPCPV6 Ack has been sent, send IPCPV6 ConfigurationRequest
                        if ( (response.packet[20] == 0x80) && (response.packet[21] == 0x57) && (response.packet[22] == 0x02) ) {
                                	
					response_additional = SendIPV6CPConfigureRequest(response);
                                        
                                        // Set source MAC address (subscriber-facing interface)
                                        for (i = 6, j = 0; i < 12; i++, j++) {
                                                response_additional.packet[i] = mac[j];            
                                        }
                                        if ((sendto(rawSocket, response_additional.packet, response_additional.length, 0, NULL, sizeof(struct sockaddr_ll))) == -1) {
                                                perror("Raw Send error - Session response");
                                                return -1;
                                } 
                        }

			// Set source MAC address (subscriber-facing interface)
                        for (i = 6, j = 0; i < 12; i++, j++) {
                                response.packet[i] = mac[j];            
                        }
                
                        if ((sendto(rawSocket, response.packet, response.length, 0, NULL, sizeof(struct sockaddr_ll))) == -1) {
                                perror("Raw Send error - Session response");
                                return -1;
                        } 

                        continue;
                }

		// Implicit discard of all other packetsi
	}

	// Release memory and close the raw socket
	free(mac);
	free(sub);
	close(rawSocket);
	close(ipSocket);

	// Finish thread
        if (pthread_join(internetPackets, NULL)) {
                perror("Thread not joined");
                return -1;
        }

	return 0;
}

void *ParseIncomingPackets(void *args) {
	
	int i, j, rawSocketInternet, bytesReceived;
	BYTE packet[PACKET_LENGTH];
	ETHERTYPE ethtype;
	IP_ADDRESS destinationIP;
	THREAD_ARGS *threadArgs = args;
	SUBSCRIBER *sub;
	BYTE *mac, *forwarding;
	unsigned short ipLength;
	
        forwarding = malloc(PACKET_LENGTH);
	sub = malloc(sizeof(SUBSCRIBER));

	// Get MAC address of interface
        if ((mac = GetMACAddress(subscriberInterface, threadArgs->rawSocket)) == NULL) return;

	// Create and bind a raw socket to the Internet-facing interface
        if ((rawSocketInternet = BindRawSocket(outgoingInterface)) == -1) return;

	printf("vbras: Dretva slusa za pakete na %s\n", outgoingInterface);

	// Listen to all incoming packets
        while(1) {

		bytesReceived = recvfrom(rawSocketInternet, &packet, PACKET_LENGTH, 0, NULL, NULL);
                if (bytesReceived == -1) {
                        perror("No packets received");
                        return;
                }

		// Discard non-IPv4 packets
		//TODO omoguciti i za IPv6
		ethtype = packet[12] * 256 + packet[13];
		if (ethtype != 0x0800) continue;

		// If the customer with the destination IP doesn't exist in the subscriber list, discard the packet implicitly 
		sub = NULL;
		//destinationIP = packet[30] * 16777216 + packet[31] * 65536 + packet[32] * 256 + packet[33];
		destinationIP = (packet[30] << 24) | (packet[31] << 16) | (packet[32] << 8) | packet[33];
		//printf("vbras: destinationIP je %u\n", destinationIP);
	
		// Lock search in the binary tree with semaphores
		sem_wait(&semaphoreTree);
		sub = FindSubscriberIP(&subscriberList, destinationIP);
		sem_post(&semaphoreTree);
			
		if (sub == NULL) continue;
		//printf("primio s Interneta %d\n", bytesReceived);
	
		// Create packet, i.e. embed incoming packet in PPPoE and PPP
        	memset(forwarding, 0, PACKET_LENGTH);
		// Set subscriber MAC address as destination MAC
		for (i = 0, j = 0; i < 6; i+=2, j++) {
			forwarding[i] = sub->mac_array[j] % 256;
			forwarding[i+1] = sub->mac_array[j] / 256;
		}
		// Set subscriber-facing interface MAC address as source MAC
		for (i = 6, j = 0; i < 12; i++, j++) {
                        forwarding[i] = mac[j];            
                }
		// Add PPPoE Session Ethertype
		Append(forwarding, 12, "\x88\x64", ETHERTYPE_LENGTH);
		// Add PPPoE header
		Append(forwarding, 14, "\x11\x00", 2);
		// Add PPPoE session ID
		forwarding[16] = sub->session_id % 256;
		forwarding[17] = sub->session_id / 256;
		// Add PPPoE length (add 2 to length of incoming IP packet)
		ipLength = packet[16] * 256 + packet[17]; 
		forwarding[18] = (ipLength + 2) / 256;
                forwarding[19] = (ipLength + 2) % 256;
		// Add PPP header
		// TODO mora biti konfigurabilno IPv4 ili IPv6
		Append(forwarding, 20, "\x00\x21", 2);
		// Add original IP packet
		for (i = 22, j = ETH_HEADER_LENGTH; j < bytesReceived; i++, j++)
			forwarding[i] = packet[j];

		// Send packet to subscriber
		//printf("saljem subscriberu %d\n", ETH_HEADER_LENGTH + PPPoE_HEADER_LENGTH + PPP_HEADER_LENGTH + ipLength);
		if ((sendto(threadArgs->rawSocket, forwarding, ETH_HEADER_LENGTH + PPPoE_HEADER_LENGTH + PPP_HEADER_LENGTH + ipLength, 0, NULL, sizeof(struct sockaddr_ll))) == -1) {
                        perror("Raw Send error - encapsulated packet toward subscriber");
			continue;
                }
	}

	free(sub);
}
