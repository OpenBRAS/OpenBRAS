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
#include "functions_auth.h"

// Function to parse incoming PPP authentication messages
// returns: PAP/CHAP response
RESPONSE ParseIncoming_Authentication(char packet[PACKET_LENGTH], int bytesReceived) {

        RESPONSE response;
	PPPoE_SESSION *session = malloc(bytesReceived - ETH_HEADER_LENGTH);

        ETHERNET_PACKET *ethPacket = malloc(bytesReceived);
        memcpy(ethPacket, packet, bytesReceived);

        response.length = 0;
        response.packet = malloc(PACKET_LENGTH);
        bzero(response.packet, PACKET_LENGTH);

        memcpy(session, ethPacket->payload, bytesReceived - ETH_HEADER_LENGTH);
	
	switch (ntohs(session->ppp_protocol)) {

                case PAP: // Parse incoming PAP messages

			switch (session->ppp_code) {
				case AUTH_REQ: // Parse incoming Authenticate-Request messages

					return ParsePAPAuthenticateRequest(ethPacket, bytesReceived);
					break;

				default: 
					break;
			}
			break;

		case CHAP: // Parse incoming CHAP messages

			// CHAP is currently not supported

			break;
	}
}

// Function to parse incoming PAP authentication requests
// returns: PAP response
RESPONSE ParsePAPAuthenticateRequest(ETHERNET_PACKET *ethPacket, int bytesReceived) {

	int i, j = 0, position, auth_ok = 0;
	BYTE peer_id_length, passwd_length;
	BYTE *peer_id_username = malloc(MAX_AUTH_LENGTH);
	BYTE *peer_id_password = malloc(MAX_AUTH_LENGTH);
        
	RESPONSE response;
        PPPoE_SESSION *session = malloc(bytesReceived - ETH_HEADER_LENGTH);

        memcpy(session, ethPacket->payload, bytesReceived - ETH_HEADER_LENGTH);
        
        response.length = 0;
        response.packet = malloc(PACKET_LENGTH);
        bzero(response.packet, PACKET_LENGTH);

	// Get Peer-ID
	peer_id_length = session->options[0];
	for (i = 0; i < peer_id_length; i++) {
		peer_id_username[i] = session->options[i + 1];
		j++;
	}
	j++;
	// Get Password
	passwd_length = session->options[j];
	for (i = 0; i < peer_id_length; i++) {
		peer_id_password[i] = session->options[i + j + 1];
	}

	auth_ok = 1;

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
	if (auth_ok) 
		{ Append(response.packet, position, "\x00\x07", 2); position += 2; }
	else {
		Append(response.packet, position, "\x00\x0a", 2); position += 2;
	}
	// Add PPP protocol
        Append(response.packet, position, "\xc0\x23", 2); position += 2;
        // Add code for Auth-Ack or Auth-Nak 
	if (auth_ok)
        	{ response.packet[position] = 0x02; position++; }
	else
        	{ response.packet[position] = 0x03; position++; }
        // Add identifier
        response.packet[position] = session->ppp_identifier; position++;
        // Add length
	if (auth_ok) {
       		response.packet[position] = 0x00; position++;
       		response.packet[position] = 0x05; position++;
	}
	else {
        	response.packet[position] = 0x00; position++;
        	response.packet[position] = 0x08; position++;
		// Add Msg-Length
        	response.packet[position] = 0x03; position++;
	}	
	// Add data
	if (auth_ok)
        	{ response.packet[position] = 0x00; position++; }
	else {
		Append(response.packet, position, "\x4e\x4f\x4b", 3); position += 3;
	}		

	free(peer_id_username);
	free(peer_id_password);

	response.length = position;
	return response;
}
