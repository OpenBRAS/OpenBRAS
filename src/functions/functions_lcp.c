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
#include "functions_ppp.h"
#include "functions_lcp.h"
#include "functions_tree.h"
#include "functions_mysql.h"

// Function which sets the Echo flag if the subscriber has replied to a Echo-Request message
void SetSubscriberEchoFlag(ETHERNET_PACKET *ethPacket) {

	LONG_MAC subscriberMAC;
	SUBSCRIBER *sub;

	// Get subscriber MAC address
	subscriberMAC = ((LONG_MAC) ntohs(ethPacket->sourceMAC[0]) << 32) | ((unsigned long) ntohs(ethPacket->sourceMAC[1]) << 16) | ((unsigned long) ntohs(ethPacket->sourceMAC[2]));

	sub = NULL;
	sem_wait(&semaphoreTree);
        sub = FindSubscriberMAC(&subscriberList, subscriberMAC);
	sem_post(&semaphoreTree);
        if (sub == NULL) return;

	sub->echoReceived = TRUE;

	return;
}

// Function which removes the subscriber from the subscriber list and updates the database (stops session and updates subscriber state)
void RemoveSubscriber(MAC_ADDRESS sourceMAC) {

	pthread_t i;
	LONG_MAC mac = 0;
	SUBSCRIBER *sub;

	mac = ((LONG_MAC) ntohs(sourceMAC[0]) << 32) | ((LONG_MAC) ntohs(sourceMAC[1]) << 16) | ((LONG_MAC) ntohs(sourceMAC[2]));
	
	// Stop subscriber thread
        sub = NULL;
	sem_wait(&semaphoreTree);
        sub = FindSubscriberMAC(&subscriberList, mac);
        sem_post(&semaphoreTree);
        if (sub == NULL) return;

	i = sub->subscriberThread;

	pthread_cancel(sub->subscriberThread);
	pthread_join(sub->subscriberThread, NULL);

	// Update number of sent and received bytes
	UpdateSentReceived(mac);
	// Stop session in database
	DeactivateSession(mac);
	// Change subscriber state
	SetSubscriberStateMAC(mac, "CLOSED");

	// Remove subscriber from binary tree
	sem_wait(&semaphoreTree);
        DeleteSubscriber(&subscriberList, mac);
        sem_post(&semaphoreTree);	
}

// Function which removes the subscriber from the subscriber list and updates the database (stops session and updates subscriber state); incoming argument is MAC address in integer form; it will be called from the subscriber thread only
void RemoveSubscriber_LongMAC(LONG_MAC mac) {

	pthread_t i;
	
	// Update number of sent and received bytes
	UpdateSentReceived(mac);
	// Stop session in database
	DeactivateSession(mac);
	// Change subscriber state
	SetSubscriberStateMAC(mac, "CLOSED");
	
	// Remove subscriber from binary tree
	sem_wait(&semaphoreTree);
        DeleteSubscriber(&subscriberList, mac);
        sem_post(&semaphoreTree);	
}

// Function which parses incoming LCP packets
// returns: LCP response
RESPONSE ParseIncoming_LCP(char packet[PACKET_LENGTH], int bytesReceived) {

	RESPONSE response;
	PPPoE_SESSION *session = malloc(bytesReceived - ETH_HEADER_LENGTH);

        ETHERNET_PACKET *ethPacket = malloc(bytesReceived);
        memcpy(ethPacket, packet, bytesReceived);

        response.length = 0;
        response.packet = malloc(PACKET_LENGTH);
        bzero(response.packet, PACKET_LENGTH);

	memcpy(session, ethPacket->payload, bytesReceived - ETH_HEADER_LENGTH);

	switch (session->ppp_code) {

		case CONF_REQ: 	// Parse an Configure-Request message and respond appropriately
			
				return ParseConfigureRequest(ethPacket, bytesReceived);
				break;
		
		case CONF_ACK:	// If Configure-Ack has been received, add state to database

				response.length = 0;
				return response;
				break;

		case CONF_NAK:	// Parse an Configure-Nak message and respond appropriately
				
				return ParseConfigureNak(ethPacket, bytesReceived);
				break;
		
		case TERM_REQ: 	// Terminate-Request has been received, remove subscriber from binary tree and respond with Terminate-Ack
			
				return SendTerminateAck(ethPacket, bytesReceived);
				break;

		case TERM_ACK: 	// If Terminate-Ack has been received, do nothing
				// Subscriber has been removed from binary tree when Terminate-Request is sent

				response.length = 0;
				return response;
				break;

		case CONF_REJ: 	// If Configure-Reject, Code-Reject or Protocol-Reject have been received, send new Configure-Request
		case CODE_REJ:	
		case PROT_REJ:	
				return SendNewConfigureRequest(ethPacket, bytesReceived);
				break;

		case ECHO_REQ: 	// If Echo-Request has been received, reply with Echo-Reply

				return SendEchoReply(ethPacket, bytesReceived);
				break;

		case ECHO_REP:	// If Echo-Reply has been received, set subscriber flag

				SetSubscriberEchoFlag(ethPacket);
				break;

		case IDENTIFICATION: // Do nothing
				break;

		default:	return SendCodeReject(ethPacket, bytesReceived);
				break;

	}

	free(session);
	return response;
}

// Function which parses LCP Configure-Request packets
// returns: LCP response
RESPONSE ParseConfigureRequest(ETHERNET_PACKET *ethPacket, int bytesReceived) {

	int i, j, optionNumber = 0, position = 0, confRej = 0, confNak = 0, missing1 = 1, missing5 = 1;
        unsigned short totalOptionLength = 4;

	RESPONSE response;
	PPPoE_SESSION *session = malloc(bytesReceived - ETH_HEADER_LENGTH);
	PPP_OPTION option[MAX_OPTION];

        response.length = 0;
        response.packet = malloc(PACKET_LENGTH);
        bzero(response.packet, PACKET_LENGTH);

	memcpy(session, ethPacket->payload, bytesReceived - ETH_HEADER_LENGTH);

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

		// Check if options 1 (MRU) and 5 (Magic-Cookie) exist and reject all other options with Configure-Reject
	        
		// If the option is MRU, check option length and check if the value is like the one in the configuration file or shorter
                // If it isn't, modify and send Configuration-Nak
                if (option[optionNumber].type == 1)  {
			missing1 = 0;
                        if (option[optionNumber].length != 4) confNak = 1;

                        if ((option[optionNumber].value[0] * 256 + option[optionNumber].value[1]) > MRU) {
				option[optionNumber].value[0] = MRU / 256;
				option[optionNumber].value[1] = MRU % 256;
				option[optionNumber].valid = NAK;
				confNak = 1;
                        }
                }
		else if (option[optionNumber].type == 5) 
			missing5 = 0;
		else {
			option[optionNumber].valid = REJECT;
			confRej = 1;
		}

                optionNumber++;
	}

	// If MRU or Magic-Cookie are missing, send Configure-Nak
	if (missing1 || missing5) confNak = 1;

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
	Append(response.packet, position, "\xc0\x21", 2); position += 2;
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
		if (missing1) {
			response.packet[position] = 0x01; position++;
			response.packet[position] = 0x04; position++;
			response.packet[position] = MRU / 256; position++;
			response.packet[position] = MRU % 256; position++;
		}
		// If Magic-Cookie is missing, add it
		if (missing5) {
			response.packet[position] = 0x05; position++;
			response.packet[position] = 0x06; position++;
			response.packet[position] = ethPacket->sourceMAC[0] % 256; position++; 
			response.packet[position] = ethPacket->sourceMAC[0] / 256; position++;
			response.packet[position] = ethPacket->sourceMAC[1] % 256; position++;
			response.packet[position] = ethPacket->sourceMAC[1] / 256; position++;
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
	// In case of Configure-Ack, return all options
	else for (i = 0; i < optionNumber; i++) {
		response.packet[position] = option[i].type; position++;
		response.packet[position] = option[i].length; position++;
		for (j = 0; j < (option[i].length - 2); j++)
			{ response.packet[position] = option[i].value[j]; position++; }
	}

	response.length = position;
	return response;
}

// Function which parses LCP Configure-Nak packets
// returns: LCP response
RESPONSE ParseConfigureNak(ETHERNET_PACKET *ethPacket, int bytesReceived) {

	int i, j, optionNumber = 0, position;
        unsigned short totalOptionLength = 4;

	RESPONSE response;
	PPPoE_SESSION *session = malloc(bytesReceived - ETH_HEADER_LENGTH);
	PPP_OPTION option[MAX_OPTION];

        response.length = 0;
        response.packet = malloc(PACKET_LENGTH);
        bzero(response.packet, PACKET_LENGTH);

	memcpy(session, ethPacket->payload, bytesReceived - ETH_HEADER_LENGTH);

	// Get all requested options in array and check which are Nak'd
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

		// If the option is MRU, accept only MRUs smaller than PPPoE_PACKET_LENGTH; otherwise limit to PPPoE_PACKETž_LENGTH
                if (option[optionNumber].type == 1)  {
                        if ((option[optionNumber].value[0] * 256 + option[optionNumber].value[1]) > MRU) {
				option[optionNumber].value[0] = MRU / 256;
				option[optionNumber].value[1] = MRU % 256;
                        }
			totalOptionLength += option[optionNumber].length;
                }
		// If the option is Authentication-Protocol, check which protocol is preferable
		if (option[optionNumber].type == 3)  {
			// If PAP is Nak'd, offer PAP (CHAP is not supported currently)
                        if (option[optionNumber].value[0] == 0xc0) {
				option[optionNumber].value[0] = 0xc0;
				option[optionNumber].value[1] = 0x23;
                        }
			// If CHAP is Nak'd, offer PAP
                        if (option[optionNumber].value[0] == 0xc2) {
				option[optionNumber].value[0] = 0xc0;
				option[optionNumber].value[1] = 0x23;
                        }
			totalOptionLength += option[optionNumber].length;
                }
		optionNumber++;
	}

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
        Append(response.packet, position, "\xc0\x21", 2); position += 2;
        // Add code (Configure-Request)
        response.packet[position] = CONF_REQ; position++;
        // Add identifier (same as in Configure-Request)
        response.packet[position] = session->ppp_identifier; position++;
	// Add length
        response.packet[position] = htons(totalOptionLength) % 256; position++;
        response.packet[position] = htons(totalOptionLength) / 256; position++;
	// Add options
	for (i = 0; i < optionNumber; i++) {
        	response.packet[position] = option[i].type; position++;
                response.packet[position] = option[i].length; position++;
                for (j = 0; j < (option[i].length - 2); j++)
                        { response.packet[position] = option[i].value[j]; position++; }
        }

	response.length = position;
	return response;
}

// Function which sends LCP Code-Reject to a subscriber
// returns: LCP Code-Reject
RESPONSE SendCodeReject(ETHERNET_PACKET *ethPacket, int bytesReceived) {
	
	int position;
	RESPONSE response;
	PPPoE_SESSION *session = malloc(bytesReceived - ETH_HEADER_LENGTH);

	memcpy(session, ethPacket->payload, bytesReceived - ETH_HEADER_LENGTH);
	
	response.length = 0;
        response.packet = malloc(PACKET_LENGTH);
        bzero(response.packet, PACKET_LENGTH);

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
        // Add payload length
	response.packet[position] = (26 + ntohs(session->ppp_length)) / 256; position++;
	response.packet[position] = (26 + ntohs(session->ppp_length)) % 256; position++;
	// Add PPP protocol
        Append(response.packet, position, "\xc0\x21", 2); position += 2;
        // Add code for Code-Reject
        response.packet[position] = 0x07; position++;
        // Add identifier
        response.packet[position] = rand() % 256; position++;
	// Add length
	response.packet[position] = (26 + ntohs(session->ppp_length)) / 256; position++;
	response.packet[position] = (26 + ntohs(session->ppp_length)) % 256; position++;
	// Add Rejected-Packet
        response.packet[position] = 0x0c; position++;
        response.packet[position] = 0x21; position++;
	response.packet[position] = session->ppp_code; position++;
	response.packet[position] = session->ppp_identifier; position++;
	response.packet[position] = session->ppp_length % 256; position++;
	response.packet[position] = session->ppp_length / 256; position++;
        Append(response.packet, position, session->options, ntohs(session->ppp_length)); position += ntohs(session->ppp_length);

	response.length = position;
	return response;
}

// Function which sends LCP Echo-Reply to a subscriber
// returns: LCP Echo-Reply
RESPONSE SendEchoReply(ETHERNET_PACKET *ethPacket, int bytesReceived) {
	
	int i, position;
	RESPONSE response;
	PPPoE_SESSION *session = malloc(bytesReceived - ETH_HEADER_LENGTH);

	memcpy(session, ethPacket->payload, bytesReceived - ETH_HEADER_LENGTH);
	
	response.length = 0;
        response.packet = malloc(PACKET_LENGTH);
        bzero(response.packet, PACKET_LENGTH);

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
        // Add payload length
	response.packet[position] = session->length % 256; position++;
	response.packet[position] = session->length / 256; position++;
	// Add PPP protocol
        Append(response.packet, position, "\xc0\x21", 2); position += 2;
        // Add code for Echo-Reply
        response.packet[position] = 0x0a; position++;
        // Add identifier
        response.packet[position] = session->ppp_identifier; position++;
	// Add length
	response.packet[position] = session->ppp_length % 256; position++;
        response.packet[position] = session->ppp_length / 256; position++;		
	// Add Magic-Number
	//for (i = 0; i < ntohs(session->ppp_length); i++)
	//	{ response.packet[position] = rand() % 256; position++; }
	response.packet[position] = ethPacket->sourceMAC[0] % 256; position++;
	response.packet[position] = ethPacket->sourceMAC[0] / 256; position++;
	response.packet[position] = ethPacket->sourceMAC[1] % 256; position++;
	response.packet[position] = ethPacket->sourceMAC[1] / 256; position++;

	response.length = position;
	return response;
}

// Function which sends LCP Terminate-Request to a subscriber
// returns: LCP Terminate-Request
RESPONSE SendTerminateRequest(ETHERNET_PACKET *ethPacket, int bytesReceived) {

        int i, position = 0;
        RESPONSE response;
        PPPoE_SESSION *session = malloc(bytesReceived - ETH_HEADER_LENGTH);

        memcpy(session, ethPacket->payload, bytesReceived - ETH_HEADER_LENGTH);

        response.length = 0;
        response.packet = malloc(PACKET_LENGTH);
        bzero(response.packet, PACKET_LENGTH);

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
        // Add payload length
	Append(response.packet, position, "\x00\x06", 2); position += 2;
        // Add PPP protocol
        Append(response.packet, position, "\xc0\x21", 2); position += 2;
        // Add code for Terminate-Request
        response.packet[position] = 0x05; position++;
	// Add identifier
        response.packet[position] = rand() / 256; position++;
        // Add length
	Append(response.packet, position, "\x00\x04", 2); position += 2;

	// Before sending Terminate-Request, remove subscriber from database
	RemoveSubscriber(ethPacket->sourceMAC);

        response.length = position;
        return response;
}

// Function which sends LCP Terminate-Ack to a subscriber
// returns: LCP Terminate-Ack
RESPONSE SendTerminateAck(ETHERNET_PACKET *ethPacket, int bytesReceived) {

	int i, position = 0;
	RESPONSE response;
	PPPoE_SESSION *session = malloc(bytesReceived - ETH_HEADER_LENGTH);

	memcpy(session, ethPacket->payload, bytesReceived - ETH_HEADER_LENGTH);
	
	response.length = 0;
        response.packet = malloc(PACKET_LENGTH);
        bzero(response.packet, PACKET_LENGTH);

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
        // Add payload length
	response.packet[position] = session->length % 256; position++;
	response.packet[position] = session->length / 256; position++;
	// Add PPP protocol
        Append(response.packet, position, "\xc0\x21", 2); position += 2;
        // Add code for Terminate-Ack
        response.packet[position] = 0x06; position++;
        // Add identifier
        response.packet[position] = session->ppp_identifier; position++;
	// Add length
	response.packet[position] = session->ppp_length % 256; position++;
        response.packet[position] = session->ppp_length / 256; position++;		
	// Add data
	for (i = 0; i < ntohs(session->ppp_length); i++) {
		response.packet[position] = session->options[i];
		position++;
	}

	// Before sending Terminate-Ack, remove subscriber from database
	RemoveSubscriber(ethPacket->sourceMAC);

	response.length = position;
        return response;
}

// Function which sends a new LCP Configure-Request to a subscriber
// returns: LCP Configure-Request
RESPONSE SendNewConfigureRequest(ETHERNET_PACKET *ethPacket, int bytesReceived) {

	int position = 0;
	RESPONSE response;
	PPPoE_SESSION *session = malloc(bytesReceived - ETH_HEADER_LENGTH);

	memcpy(session, ethPacket->payload, bytesReceived - ETH_HEADER_LENGTH);
	
	response.length = 0;
        response.packet = malloc(PACKET_LENGTH);
        bzero(response.packet, PACKET_LENGTH);

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
        // Add payload lengthi (20)
	response.packet[position] = 0x00; position++;
	response.packet[position] = 0x14; position++;
	// Add PPP protocol
        Append(response.packet, position, "\xc0\x21", 2); position += 2;
	// Add code for Configure-Request
        response.packet[position] = 0x01; position++;
	// Add identifier
	response.packet[position] = rand() / 256; position++;
	// Add length (18)
	response.packet[position] = 0x00; position++;
	response.packet[position] = 0x12; position++;
	// Add configuration options
	// Add MRU
	Append(response.packet, position, "\x01\x04", 2); position += 2;
	response.packet[position] = MRU / 256; position++;
        response.packet[position] = MRU % 256; position++;
	// Add authentication protocol
	Append(response.packet, position, "\x03\x04\xc0\x23", 4); position += 4;
	// Add Magic-Number
	Append(response.packet, position, "\x05\x06", 2); position += 2;
	response.packet[position] = ethPacket->sourceMAC[0] % 256; position++;
        response.packet[position] = ethPacket->sourceMAC[0] / 256; position++;
        response.packet[position] = ethPacket->sourceMAC[1] % 256; position++;
        response.packet[position] = ethPacket->sourceMAC[1] / 256; position++;	

	response.length = position;
	return response;	
}

// Function which sends LCP Configure-Request to a subscriber
// returns: LCP Configure-Request
RESPONSE SendConfigureRequest(RESPONSE response) {

	int i, position;
	RESPONSE response_additional;

	response_additional.length = 0;
        response_additional.packet = malloc(PACKET_LENGTH);
        bzero(response_additional.packet, PACKET_LENGTH);

	// Copy first 19 bytes to Configure-Request
	for (i = 0; i < 19; i++)
		response_additional.packet[i] = response.packet[i];
	position = 18;
	
        // Add payload length (20)
	response_additional.packet[position] = 0x00; position++;
	response_additional.packet[position] = 0x14; position++;
	// Add PPP protocol
        Append(response_additional.packet, position, "\xc0\x21", 2); position += 2;
	// Add code for Configure-Request
        response_additional.packet[position] = 0x01; position++;
	// Add identifier
	response_additional.packet[position] = rand() / 256; position++;
	// Add length (18)
	response_additional.packet[position] = 0x00; position++;
	response_additional.packet[position] = 0x12; position++;
	// Add configuration options
	// Add MRU
	Append(response_additional.packet, position, "\x01\x04", 2); position += 2;
	response_additional.packet[position] = MRU / 256; position++;
	response_additional.packet[position] = MRU % 256; position++;
	// Add authentication protocol
	Append(response_additional.packet, position, "\x03\x04\xc0\x23", 4); position += 4;
	// Add Magic-Number
	Append(response_additional.packet, position, "\x05\x06", 2); position += 2;
	response_additional.packet[position] = response.packet[2]; position++;
        response_additional.packet[position] = response.packet[3]; position++;
        response_additional.packet[position] = response.packet[4]; position++;
        response_additional.packet[position] = response.packet[5]; position++;
	
	response_additional.length = position;
	return response_additional;
}
