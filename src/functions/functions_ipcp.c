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
#include "functions_tree.h"

// Function which adds a new subscriber to the subscriber list
void AddNewSubscriber(ETHERNET_PACKET *ethPacket, int bytesReceived) {

	int i, j;
	unsigned long mac = 0;
	MAC_ADDRESS mac_array;
	IP_ADDRESS ip = 0;

	PPPoE_SESSION *session = malloc(bytesReceived - ETH_HEADER_LENGTH);
	PPP_OPTION option;
	memcpy(session, ethPacket->payload, bytesReceived - ETH_HEADER_LENGTH);

	// Get the subscriber MAC address in unsigned long format
	mac = ((unsigned long) ntohs(ethPacket->sourceMAC[0]) << 32) | ((unsigned long) ntohs(ethPacket->sourceMAC[1]) << 16) | ((unsigned long) ntohs(ethPacket->sourceMAC[2]));

	// Get MAC address in array format
	for (i = 0; i < 3; i++) mac_array[i] = ethPacket->sourceMAC[i];

	// Get subscriber IP address
	i = 0;
        while (i < (ntohs(session->ppp_length) - 4)) {
                // Get OPTION_TYPE
                option.type = session->options[i];

                // Get OPTION_LENGTH
                option.length = session->options[i+1];

                // Get OPTION_VALUE
                i = i + 2;
                j = 0;
                bzero(option.value, MAX_OPTION_LENGTH);
                while (j < (option.length - 2)) {
                        option.value[j] = session->options[i];
                        i++;
                        j++;
                }

		if (option.type == 3) ip = (option.value[0] << 24) | (option.value[1] << 16) | (option.value[2] << 8) | option.value[3];
	}

	if ( (ip == 0) || (mac == 0) ) return;

	sem_wait(&semaphoreTree);
	AddSubscriber(&subscriberList, mac, mac_array, ip, session->session_id);
	sem_post(&semaphoreTree);
}

// Functions which checks which IP address is available
// returns: first available IP address from pool
unsigned int GetFreeIPAddress() {

	unsigned int i, ip1, ip2, ip3, ip4, length, ip, mask, length_binary, tmp;
	SUBSCRIBER *tmpSub;

	// Scan the local pool and convert the prefix/length format to a mask
	sscanf(IPv4_pool, "%d.%d.%d.%d/%d", &ip1, &ip2, &ip3, &ip4, &length);
	ip = (ip1 << 24) | (ip2 << 16) | (ip3 << 8) | ip4;

	length_binary = pow(2, (32 - length)) - 1;
	mask = ip & (~length_binary);

	// Search for available IP addresses in the binary tree
	for (i = 1; i <= length_binary; i++) {
		tmp = mask + i;
	
		sem_wait(&semaphoreTree);
		tmpSub = FindSubscriberIP(&subscriberList, tmp);
		sem_post(&semaphoreTree);

		if (tmpSub == NULL) return tmp;
	}

	// If there is no available IP address, return 0
	return 0;
}

// Function which parses incoming IPCP packets
// returns: IPCP response
RESPONSE ParseIncoming_IPCP(char packet[PACKET_LENGTH], int bytesReceived) {

	RESPONSE response;
	PPPoE_SESSION *session = malloc(bytesReceived - ETH_HEADER_LENGTH);

        ETHERNET_PACKET *ethPacket = malloc(bytesReceived);
        memcpy(ethPacket, packet, bytesReceived);

        response.length = 0;
        response.packet = malloc(PACKET_LENGTH);
        bzero(response.packet, PACKET_LENGTH);

	memcpy(session, ethPacket->payload, bytesReceived - ETH_HEADER_LENGTH);

	switch (session->ppp_code) {

		case CONF_REQ: 	// Parse an IPCP Configure-Request message and respond appropriately
			
				return ParseIPCPConfigureRequest(ethPacket, bytesReceived);
				break;
		
		case CONF_ACK:	// If IPCP Configure-Ack has been received, don't send any response

				response.length = 0;
				return response;
				break;

		default:	
				break;

	}

	free(session);
	return response;
}

// Function which parses IPCP Configure-Request packets
// returns: IPCP response
RESPONSE ParseIPCPConfigureRequest(ETHERNET_PACKET *ethPacket, int bytesReceived) {

	int i, j, optionNumber = 0, position = 0, confRej = 0, confNak = 0, missing3 = 1, missing129 = 1;
        unsigned short totalOptionLength = 4;
	unsigned int ip;
	BYTE ip0, ip1, ip2, ip3;

	RESPONSE response;
	PPPoE_SESSION *session = malloc(bytesReceived - ETH_HEADER_LENGTH);
	PPP_OPTION option[MAX_OPTION];

        response.length = 0;
        response.packet = malloc(PACKET_LENGTH);
        bzero(response.packet, PACKET_LENGTH);

	memcpy(session, ethPacket->payload, bytesReceived - ETH_HEADER_LENGTH);

	// Get available IP address; if not available, send Terminate Request
	ip = GetFreeIPAddress();
	if (ip == 0) return SendTerminateRequest(ethPacket, bytesReceived);

	ip0 = ip >> 24;
	ip1 = (ip >> 16) & 255;
	ip2 = (ip >> 8) & 255;
	ip3 = ip & 255;	

	// Get all requested options in array and check which are present
	i = 0;
        while (i < (ntohs(session->ppp_length) - 4)) {
        	// Get OPTION_TYPE
                option[optionNumber].type = session->options[i];

                // Get OPTION_LENGTH
                option[optionNumber].length = session->options[i+1];
                                                
                // Get OPTION_VALUE
                i = i + 2; 
                j = 0;
                bzero(option[optionNumber].value, MAX_OPTION_LENGTH);
		while (j < (option[optionNumber].length - 2)) {
                	option[optionNumber].value[j] = session->options[i];
                        i++; 
                        j++;
                }

		// Check if options 3 (IP address) and 129 (Primary DNS) exist and reject all other options with Configure-Reject
	        
		// If the option is IP address, check if it's the one assigned
                // If it isn't, modify and send Configuration-Nak
                if (option[optionNumber].type == 3)  {
			missing3 = 0;
                        if (option[optionNumber].length != 6) confNak = 1;

                        if ((option[optionNumber].value[0] != ip0) || (option[optionNumber].value[1] != ip1) || (option[optionNumber].value[2] != ip2) || (option[optionNumber].value[3] != ip3)) {
				option[optionNumber].value[0] = ip0;
				option[optionNumber].value[1] = ip1;
				option[optionNumber].value[2] = ip2;
				option[optionNumber].value[3] = ip3;
				option[optionNumber].valid = NAK;
				confNak = 1;
                        }
                }
		else if (option[optionNumber].type == 129) { 
			missing129 = 0;
                        if (option[optionNumber].length != 6) confNak = 1;

                        if ((option[optionNumber].value[0] != 8) || (option[optionNumber].value[1] != 8) || (option[optionNumber].value[2] != 8) || (option[optionNumber].value[3] != 8)) {
				option[optionNumber].value[0] = 8;
				option[optionNumber].value[1] = 8;
				option[optionNumber].value[2] = 8;
				option[optionNumber].value[3] = 8;
				option[optionNumber].valid = NAK;
				confNak = 1;
                        }
		}
		else {
			option[optionNumber].valid = REJECT;
			confRej = 1;
		}

                optionNumber++;
	}

	// If MRU or Magic-Cookie are missing, send Configure-Nak
	if (missing3 || missing129) confNak = 1;

	// If there are options to be rejected, add up their length
	if (confRej) {
		for (i = 0; i < optionNumber; i++)
			if (option[i].valid == REJECT)
				totalOptionLength += option[i].length;
	}
	// If there are options to be Nak'd, add up their length
	else if (confNak) {
		for (i = 0; i < optionNumber; i++)
			if (option[i].valid == NAK)
				totalOptionLength += option[i].length;
	}
	// If the response is Ack, the length is copied
	else totalOptionLength = ntohs(session->ppp_length);

        // Create reply packet
        position = 0;
        // Add destination MAC       
        memcpy(response.packet, ethPacket->sourceMAC, MAC_ADDRESS_LENGTH); position += MAC_ADDRESS_LENGTH;
        // Add placeholder for source MAC
        Append(response.packet, position, "\x00\x00\x00\x00\x00\x00", MAC_ADDRESS_LENGTH); position += MAC_ADDRESS_LENGTH;
        // Add ethertype
        Append(response.packet, position, "\x88\x64", ETHERTYPE_LENGTH); position += ETHERTYPE_LENGTH;		
	// Add PPPoE header
        Append(response.packet, position, "\x11", 1); position++;
        Append(response.packet, position, "\x00", 1); position++;
	// Add PPPoE SESSION_ID
	response.packet[position] = session->session_id % 256; position++;
        response.packet[position] = session->session_id / 256; position++;
	// Add PPPoE payload length 
	response.packet[position] = htons(totalOptionLength + 2) % 256; position++;
	response.packet[position] = htons(totalOptionLength + 2) / 256; position++;
	// Add PPP protocol
	Append(response.packet, position, "\x80\x21", 2); position += 2;
	// Add code (Configure-Reject, Configure-Nak or Configure-Ack)
	if (confRej) response.packet[position] = 0x04;
	else if (confNak) response.packet[position] = 0x03;
	else response.packet[position] = 0x02;
	position++;
	// Add identifier (same as in Configure-Request)
	response.packet[position] = session->ppp_identifier; position++;
	// Add length
	response.packet[position] = htons(totalOptionLength) % 256; position++;
	response.packet[position] = htons(totalOptionLength) / 256; position++;
	// Add options		
	// In case of Configure-Reject, return only rejected options
	if (confRej) {
		for (i = 0; i < optionNumber; i++)
			if (option[i].valid == REJECT) {
				response.packet[position] = option[i].type; position++;
				response.packet[position] = option[i].length; position++;
				for (j = 0; j < (option[i].length - 2); j++)
					{ response.packet[position] = option[i].value[j]; position++; }
			}
	}
	// In case of Configure-Nak, return only Nak'd options
	else if (confNak) {
		// If MRU is missing, add it
		if (missing3) {
			response.packet[position] = 0x01; position++;
			response.packet[position] = 0x04; position++;
			response.packet[position] = 0x05; position++;
			response.packet[position] = 0xd4; position++;
		}
		// If Magic-Cookie is missing, add it
		if (missing129) {
			response.packet[position] = 0x05; position++;
			response.packet[position] = 0x06; position++;
			response.packet[position] = rand() % 256; position++; 
			response.packet[position] = rand() % 256; position++;
			response.packet[position] = rand() % 256; position++;
			response.packet[position] = rand() % 256; position++;
		}
		// Add other Nak'd options
		for (i = 0; i < optionNumber; i++)
			if (option[i].valid == NAK) {
				response.packet[position] = option[i].type; position++;
				response.packet[position] = option[i].length; position++;
				for (j = 0; j < (option[i].length - 2); j++)
					{ response.packet[position] = option[i].value[j]; position++; }
			}
	}
	// In case of Configure-Ack, return all options and add new subscriber to list
	else {
		for (i = 0; i < optionNumber; i++) {
			response.packet[position] = option[i].type; position++;
			response.packet[position] = option[i].length; position++;
			for (j = 0; j < (option[i].length - 2); j++)
				{ response.packet[position] = option[i].value[j]; position++; }
		}
		AddNewSubscriber(ethPacket, bytesReceived);
	}

	response.length = position;
	return response;
}

// Function which sends IPCP Configure-Request according to the previously sent packet towards the subscriber
// returns: IPCP Configure-Request
RESPONSE SendIPCPConfigureRequest(RESPONSE response) {

	int i, position;
	RESPONSE response_additional;

	response_additional.length = 0;
        response_additional.packet = malloc(PACKET_LENGTH);
        bzero(response_additional.packet, PACKET_LENGTH);

	// Copy first 19 bytes to Configure-Request
	for (i = 0; i < 19; i++)
		response_additional.packet[i] = response.packet[i];
	position = 18;
	
        // Add payload length (12)
	response_additional.packet[position] = 0x00; position++;
	response_additional.packet[position] = 0x0c; position++;
	// Add PPP protocol
        Append(response_additional.packet, position, "\x80\x21", 2); position += 2;
	// Add code for Configure-Request
        response_additional.packet[position] = 0x01; position++;
	// Add identifier
	response_additional.packet[position] = rand() / 256; position++;
	// Add length (10)
	response_additional.packet[position] = 0x00; position++;
	response_additional.packet[position] = 0x0a; position++;
	// Add configuration option for IP address
	Append(response_additional.packet, position, "\x03\x06", 2); position += 2;
	response_additional.packet[position] = 0x10; position++;
	response_additional.packet[position] = 0x11; position++;
	response_additional.packet[position] = 0x12; position++;
	response_additional.packet[position] = 0x13; position++;

	response_additional.length = position;
	return response_additional;
}
