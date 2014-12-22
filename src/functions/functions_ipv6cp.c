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
#include "functions_ipv6cp.h"

// Function to parse incoming IPV6CP packets
// returns: IPV6CP response
RESPONSE ParseIncoming_IPV6CP(char packet[PACKET_LENGTH], int bytesReceived) {

	RESPONSE response;
	PPPoE_SESSION *session = malloc(bytesReceived - ETH_HEADER_LENGTH);

        ETHERNET_PACKET *ethPacket = malloc(bytesReceived);
        memcpy(ethPacket, packet, bytesReceived);

        response.length = 0;
        response.packet = malloc(PACKET_LENGTH);
        bzero(response.packet, PACKET_LENGTH);

	memcpy(session, ethPacket->payload, bytesReceived - ETH_HEADER_LENGTH);

	switch (session->ppp_code) {

		case CONF_REQ: 	// Return IPV6CP Terminate-Request message because IPv6 is not yet implemented
			
				return SendIPv6CPTerminateRequest(ethPacket, bytesReceived);
				
				break;
		
		case TERM_REQ:  // If Terminate-Request has been received, respond with Terminate-Ack

                                return SendIPV6CPTerminateAck(ethPacket, bytesReceived);
                                break;

		case CONF_ACK:
                case TERM_ACK:  // If Configure-Ack or Terminate-Ack have been received, don't send any response

                                response.length = 0;
                                return response;
                                break;

		default:	
				break;

	}

	free(session);
	return response;
}

// Function to send IPV6CP Terminate-Ack
// returns: IPV6CP Terminate-Ack
RESPONSE SendIPV6CPTerminateAck(ETHERNET_PACKET *ethPacket, int bytesReceived) {

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
        Append(response.packet, position, "\x80\x57", 2); position += 2;
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

	// Before sending Terminate-Request, remove subscriber from database
        RemoveSubscriber(ethPacket->sourceMAC);

        response.length = position;
        return response;
}

// Function to send IPV6CP Terminate-Request
// returns: IPV6CP Terminate-Request
RESPONSE SendIPv6CPTerminateRequest(ETHERNET_PACKET *ethPacket, int bytesReceived) {

	int i, position;

	RESPONSE response;
        PPPoE_SESSION *session = malloc(bytesReceived - ETH_HEADER_LENGTH);
        PPP_OPTION option[MAX_OPTION];

        response.length = 0;
        response.packet = malloc(PACKET_LENGTH);
        bzero(response.packet, PACKET_LENGTH);

        memcpy(session, ethPacket->payload, bytesReceived - ETH_HEADER_LENGTH);

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
        response.packet[position] = session->length % 256; position++;
        response.packet[position] = session->length / 256; position++;
        // Add PPP protocol
        Append(response.packet, position, "\x80\x57", 2); position += 2;
        // Add code (Terminate-Request)
        response.packet[position] = 0x05; position++;
	// Add identifier
        response.packet[position] = rand() % 256; position++;
        // Add length
        response.packet[position] = 0x00; position++;
        response.packet[position] = 0x04; position++;

	// Before sending Terminate-Request, remove subscriber from database
        RemoveSubscriber(ethPacket->sourceMAC);

	response.length = position;
        return response;
}
