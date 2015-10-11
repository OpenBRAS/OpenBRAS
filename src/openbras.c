/*
Copyright (C) 2014 Branimir Rajtar

This file is part of OpenBRAS.

OpenBRAS is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

OpenBRAS is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with OpenBRAS. If not, see <http://www.gnu.org/licenses/>.
 */

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
#include "functions_mysql.h"
#include "functions_radius.h"

// Declaration of thread for listening of incoming packets and the structure for passing thread arguments
void *ParseIncomingPackets(void *args);
typedef struct {
	LONG_MAC mac;
	int rawSocket;
} THREAD_ARGS;

// Main thread in the program
int main(int argc, char **argv)
{
	int i, j, tmp, bytesReceived;
	BYTE packet[PACKET_LENGTH], packet_ip[PACKET_LENGTH];
	ETHERTYPE ethtype;
	MAC_ADDRESS sourceMAC;
	PPP_PROTOCOL pppProto;
	RESPONSE response, response_additional;
	struct sockaddr_in sin;
	struct ifreq if_mac;
	BYTE *mac;
	LONG_MAC subscriberMAC;
	SUBSCRIBER *sub;
	FILE *fd;
	pthread_t internetPackets, tmpThread, radiusThread;
	THREAD_ARGS threadArgs;

	sub = malloc(sizeof(SUBSCRIBER));

	// Open syslog for error logging
	openlog("openvbras", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_USER);

	// The list of subscribers is empty at the beginning
	subscriberList = NULL;

	// Read configuration file
	if (argc < 2) fd = fopen("openbras.conf", "r");
	else if (argc == 2) fd = fopen(argv[1], "r");
	else {
		syslog(LOG_ERR, "Usage: sudo ./openbras [CONFIGURATION_FILE]\n");
		return -1;
	}
	if (fd == NULL) {
		syslog(LOG_ERR, "Configuration file not found");
		return -1;
	}
	SetExternVariables(fd);

	// Create and bind a raw socket to the subscriber-facing interface
	if ((rawSocket = BindRawSocket(subscriberInterface)) == -1) return -1;

	// Create socket for outgoing IP packets
	if ((ipSocket = CreateIPSocket(outgoingInterface)) == -1) return -1;
	memset (&sin, 0, sizeof (struct sockaddr_in));
	sin.sin_family = AF_INET;

	// Get the MAC address of subscriber-facing interface
	if ((mac = GetMACAddress(subscriberInterface, rawSocket)) == NULL) return -1;

	// Start thread for listening packets from the Internet-facing interface
	threadArgs.rawSocket = rawSocket;
	if (pthread_create(&internetPackets, NULL, ParseIncomingPackets, &threadArgs)) {
		syslog(LOG_ERR, "Listening thread not created");
		return -1;
	}

	// If Radius authentications is selected, create and bind a UDP socket to the Radius-facing interface and start Radius-listening thread
	if (radiusAuth) {
		if ((radiusSocket = BindUDPSocket(radiusInterface)) == -1) return -1;
		if (pthread_create(&radiusThread, NULL, &ListenToRadius, NULL)) {
			syslog(LOG_ERR, "Thread for listening to packets from Radius server not created");
			return -1;
		}
	}
	// Otherwise, connect to the database
	else
	{
		ConnectToDatabase();
	}

	// Initiate semaphores
	sem_init(&semaphoreTree, 0, 1);

	// Log start of program
	syslog(LOG_INFO, "OpenBRAS started");
	syslog(LOG_INFO, "Listening for subscribers on %s", subscriberInterface);

	// Listen to all incoming packets
	while(1) {

		bytesReceived = recvfrom(rawSocket, &packet, PACKET_LENGTH, 0, NULL, NULL);
		if (bytesReceived == -1) {
			syslog(LOG_NOTICE, "No packets received from subscriber");
			continue;
		}

		// Find relevant fields for if-else tree, the packet ethernet type and ppp protocol
		ethtype = (packet[12] << 8) | packet[13];

		// Discard packets with non-relevant ethtypes
		if ( (!(ethtype ^ ETH_P_PPP_SES)) & (!(ethtype ^ ETH_P_PPP_DISC)) ) continue;

		pppProto = (packet[20] << 8) | packet[21];

		// If incoming packet is regular PPPoE traffic, verify the source MAC address and forward to the Internet
		// Regular PPPoE traffic == ethernet type 0x8864 and PPP protocol type IPv4
		if ( (!(ethtype ^ ETH_P_PPP_SES)) & (!(pppProto ^ 0x0021)) ) {

			sourceMAC[0] = packet[6] + (packet[7] << 8);
			sourceMAC[1] = packet[8] + (packet[9] << 8);
			sourceMAC[2] = packet[10] + (packet[11] << 8);
			subscriberMAC = ((LONG_MAC) ntohs(sourceMAC[0]) << 32) | ((LONG_MAC) ntohs(sourceMAC[1]) << 16) | ((LONG_MAC) ntohs(sourceMAC[2]));

			// If the source MAC address doesn't belong to a registered subscriber, discard the packet implicitly
			sub = NULL;
			sem_wait(&semaphoreTree);
			sub = FindSubscriberMAC(&subscriberList, subscriberMAC);
			sem_post(&semaphoreTree);
			if ((sub == NULL) || (sub->authenticated == 0)) continue;

			// Remove Ethernet, PPPoE and PPP headers
			tmp = bytesReceived - ETH_HEADER_LENGTH - PPPoE_HEADER_LENGTH - PPP_HEADER_LENGTH;
			for (i = 0; i < tmp; i++)
				packet_ip[i] = packet[i + ETH_HEADER_LENGTH + PPPoE_HEADER_LENGTH + PPP_HEADER_LENGTH];

			// Send packet to the destination IP address, i.e. towards the Internet	and update database
			sin.sin_addr.s_addr = (packet_ip[16] << 24) | (packet_ip[17] << 16) | (packet_ip[18] << 8) | packet_ip[19];
			if (sendto(ipSocket, packet_ip, tmp - 4, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0)  {
				syslog(LOG_NOTICE, "Sending of packet to the Internet failed");
				continue;
			}
			// Update sent bytes number
			sub->bytesSent += (tmp -4);

			continue;
		}

		// If the ethertype is PPPoE, but not regular traffic, parse on the control plane

		// Parse control plane packets with PPPoE Discover Ethertype
		else if (!(ethtype ^ ETH_P_PPP_DISC)) {

			response = ParseIncoming_Discover(packet, bytesReceived);
			if (response.length == 0) continue;

			// Set source MAC address (subscriber-facing interface)
			for (i = 6, j = 0; i < 12; i++, j++) {
				response.packet[i] = mac[j];
			}

			// Send response to Discover
			if ((sendto(rawSocket, response.packet, response.length, 0, NULL, sizeof(struct sockaddr_ll))) == -1) {
				syslog(LOG_NOTICE, "Error sending response to PPPoE discover message");
			}

			continue;
		}

		// Parse control plane packets with PPPoE Session Ethertype
		else if (!(ethtype ^ ETH_P_PPP_SES)) {

			response = ParseIncoming_Session(packet, bytesReceived);
			if (response.length == 0) continue;

			// If LCP Configure-Ack has been sent, send LCP Configure-Request
			if ( (response.packet[20] == 0xc0) && (response.packet[21] == 0x21) && (response.packet[22] == 0x02) ) {

				response_additional = SendConfigureRequest(response);

				// Set source MAC address (subscriber-facing interface)
				for (i = 6, j = 0; i < 12; i++, j++) {
					response_additional.packet[i] = mac[j];
				}
				if ((sendto(rawSocket, response_additional.packet, response_additional.length, 0, NULL, sizeof(struct sockaddr_ll))) == -1) {
					syslog(LOG_NOTICE, "Error sending response to PPPoE Session message");
					continue;
				}
			}

			// If IPCP Configure-Ack has been sent, send IPCP Configure-Request and start new customer thread
			if ( (response.packet[20] == 0x80) && (response.packet[21] == 0x21) && (response.packet[22] == 0x02) ) {

				response_additional = SendIPCPConfigureRequest(response);

				// Set source MAC address (subscriber-facing interface)
				for (i = 6, j = 0; i < 12; i++, j++) {
					response_additional.packet[i] = mac[j];
				}
				if ((sendto(rawSocket, response_additional.packet, response_additional.length, 0, NULL, sizeof(struct sockaddr_ll))) == -1) {
					syslog(LOG_NOTICE, "Error sending response to PPPoE Session message");
					continue;
				}

				// Start customer thread with customer MAC address and raw socket as arguments
				memset(&threadArgs, 0, sizeof(THREAD_ARGS));
				threadArgs.mac = ((LONG_MAC)response.packet[0] << 40) | ((LONG_MAC)response.packet[1] << 32) | ((LONG_MAC)response.packet[2] << 24) | ((LONG_MAC)response.packet[3] << 16) | ((LONG_MAC)response.packet[4] << 8) | (LONG_MAC)response.packet[5];
				threadArgs.rawSocket = rawSocket;

				if (pthread_create(&tmpThread, NULL, SubscriberLCPEchoThread, &threadArgs)) {
					syslog(LOG_WARNING, "Subscriber thread not created");
					continue;
				}
			}

			// Set source MAC address (subscriber-facing interface)
			for (i = 6, j = 0; i < 12; i++, j++) {
				response.packet[i] = mac[j];
			}

			if ((sendto(rawSocket, response.packet, response.length, 0, NULL, sizeof(struct sockaddr_ll))) == -1) {
				syslog(LOG_WARNING, "Subscriber thread not created");
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

	// Close syslog
	closelog();

	// Finish thread
	if (pthread_join(internetPackets, NULL)) {
		syslog(LOG_NOTICE, "Thread not joined");
	}

	return 0;
}

// Function to receive packets from the Internet and forward them to the subscribers
void *ParseIncomingPackets(void *args) {

	int i, j, bytesReceived;
	BYTE packet[PACKET_LENGTH];
	ETHERTYPE ethtype;
	IP_ADDRESS destinationIP;
	THREAD_ARGS *threadArgs = args;
	SUBSCRIBER *sub;
	BYTE *mac, *forwarding;
	unsigned short ipLength;

	forwarding = malloc(PACKET_LENGTH);
	sub = malloc(sizeof(SUBSCRIBER));

	// Get MAC address of the subscriber-facing interface
	if ((mac = GetMACAddress(subscriberInterface, threadArgs->rawSocket)) == NULL) return NULL;

	// Create and bind a raw socket to the Internet-facing interface
	if ((rawSocketInternet = BindRawSocket(outgoingInterface)) == -1) return NULL;

	// Log start of thread
	syslog(LOG_INFO, "Listening for incoming Internet packets on %s", outgoingInterface);

	// Listen to all incoming packets
	while(1) {

		bytesReceived = recvfrom(rawSocketInternet, &packet, PACKET_LENGTH, 0, NULL, NULL);
		if (bytesReceived == -1) {
			syslog(LOG_NOTICE, "No packets received from the Internet");
			continue;
		}

		// Discard non-IPv4 packets
		ethtype = (packet[12] << 8) | packet[13];
		if (ethtype != 0x0800) continue;

		// If the customer with the destination IP doesn't exist in the subscriber list, discard the packet implicitly 
		sub = NULL;
		destinationIP = (packet[30] << 24) | (packet[31] << 16) | (packet[32] << 8) | packet[33];

		sem_wait(&semaphoreTree);
		sub = FindSubscriberIP(&subscriberList, destinationIP);
		sem_post(&semaphoreTree);
		if (sub == NULL) continue;

		// Create packet to send to subscriber, i.e. embed incoming packet in PPPoE and PPP
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
		forwarding[12] = 0x88;
		forwarding[13] = 0x64;
		// Add PPPoE header
		forwarding[14] = 0x11;
		forwarding[15] = 0x00;
		// Add PPPoE session ID
		forwarding[16] = sub->session_id % 256;
		forwarding[17] = sub->session_id / 256;
		// Add PPPoE length (add 2 to length of incoming IP packet)
		ipLength = (packet[16] << 8) + packet[17]; 
		forwarding[18] = (ipLength + 2) / 256;
		forwarding[19] = (ipLength + 2) % 256;
		// Add PPP header
		forwarding[20] = 0x00;
		forwarding[21] = 0x21;
		// Add original IP packet
		for (i = 22, j = ETH_HEADER_LENGTH; j < bytesReceived; i++, j++)
			forwarding[i] = packet[j];

		// Send packet to subscriber and update database
		if ((sendto(threadArgs->rawSocket, forwarding, ETH_HEADER_LENGTH + PPPoE_HEADER_LENGTH + PPP_HEADER_LENGTH + ipLength, 0, NULL, sizeof(struct sockaddr_ll))) == -1) {
			syslog(LOG_NOTICE, "Packet not sent towards the subscriber");
			continue;
		}
		// Update received bytes
		sub->bytesReceived += ipLength;
	}

	free(sub);
}
