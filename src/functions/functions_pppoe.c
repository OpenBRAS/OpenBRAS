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

// Function which parses incoming PPPoE Discover packets
// returns: PPPoE Discover response
RESPONSE ParseIncoming_Discover(char packet[PACKET_LENGTH], int bytesReceived) {
	
	int i, j, tagNumber = 0, position = 0;
	unsigned short totalTagLength = 0;

	RESPONSE response;
	PPPoE_DISCOVER *discover = malloc(bytesReceived - ETH_HEADER_LENGTH);
	PPPoE_DISCOVER_TAG tag[MAX_TAG];
	
	ETHERNET_PACKET *ethPacket = malloc(bytesReceived);
	memcpy(ethPacket, packet, bytesReceived);

	response.length = 0;
	response.packet = malloc(PACKET_LENGTH);
	bzero(response.packet, PACKET_LENGTH);
	
	// If the Ethertype is discover
	if (!(htons(ethPacket->ethType) ^ ETH_P_PPP_DISC)) {
		memcpy(discover, ethPacket->payload, bytesReceived - ETH_HEADER_LENGTH);
		
		// If the version-type field is not 0x11, it's an unvalid PPPoE discover packet, don't reply
		if (discover->versionType ^ 0x11) {
			return response;
		}

		switch (discover->code) {
		
			case PADI: 	// Answer with PADO
					
					// Parse PPPoE Discover tags, i.e. copy all tags to PPPoE_DISCOVER_TAG array
					i = 0;
					while (i < ntohs(discover->length)) {
						// Get TAG_TYPE
						tag[tagNumber].type = discover->tags[i] * 256 + discover->tags[i+1];
		
						// Get TAG_LENGTH
						tag[tagNumber].length = discover->tags[i+2] * 256 + discover->tags[i+3];
						
						// Get TAG_VALUE
						i = i + 4; 
						j = 0;
						bzero(tag[tagNumber].value, MAX_TAG_LENGTH);
						while (j < tag[tagNumber].length) {
							tag[tagNumber].value[j] = discover->tags[i];
							i++; 
							j++;
						}
						
						// If the tags are Service-Name, Host-Uniq tag or Relay-Session-Id, include their size in total tag length
						if ((tag[tagNumber].type == 0x0101) | (tag[tagNumber].type == 0x0103) | (tag[tagNumber].type == 0x0110)) {
							totalTagLength += (tag[tagNumber].length + 4);
						}						

						tagNumber++;
					}
					
					// Create reply packet
					position = 0;
					// Add destination MAC	
					memcpy(response.packet, ethPacket->sourceMAC, MAC_ADDRESS_LENGTH); position += MAC_ADDRESS_LENGTH;
					// Add placeholder for source MAC
					Append(response.packet, position, "\x00\x00\x00\x00\x00\x00", MAC_ADDRESS_LENGTH); position += MAC_ADDRESS_LENGTH;
					// Add ethertype
					Append(response.packet, position, "\x88\x63", ETHERTYPE_LENGTH); position += ETHERTYPE_LENGTH;
					// Add PPPoE PADO header
					Append(response.packet, position, "\x11", 1); position++;
					Append(response.packet, position, "\x07\x00\x00", 3); position += 3;
					// Add length (+ AC-Name and AC-Cookie)
					totalTagLength += (4 + strlen(AC_Name) + 6);
					response.packet[position] = (unsigned char) totalTagLength / 256; position++;
					response.packet[position] = (unsigned char) totalTagLength % 256; position++;
					// Add AC-Name tag
					Append(response.packet, position, "\x01\x02", 2); position += 2;
					response.packet[position] = (unsigned char) strlen(AC_Name) / 256; position++;
					response.packet[position] = (unsigned char) strlen(AC_Name) % 256; position++;
					Append(response.packet, position, AC_Name, strlen(AC_Name)); position += strlen(AC_Name);
					// Add AC-Cookie
					Append(response.packet, position, "\x01\x04", 2); position += 2;
					Append(response.packet, position, "\x00\x02", 2); position += 2;
					srand(time(NULL));
					response.packet[position] = rand(); position++;
					response.packet[position] = rand() % 123; position++;
					// Add Service-Name, Host-Uniq tag and Relay-Session-Id, if sent in PADI
					for(i = 0; i < tagNumber; i++) {
						if (tag[i].type == 0x0101) {
							Append(response.packet, position, "\x01\x01", 2); position += 2;
							response.packet[position] = (unsigned char) tag[i].length / 256; position++;
							response.packet[position] = (unsigned char) tag[i].length % 256; position++;
							Append(response.packet, position, tag[i].value, tag[i].length); position += tag[i].length;
						}
						if (tag[i].type == 0x0103) {
							Append(response.packet, position, "\x01\x03", 2); position += 2;
							response.packet[position] = (unsigned char) tag[i].length / 256; position++;
							response.packet[position] = (unsigned char) tag[i].length % 256; position++;
							Append(response.packet, position, tag[i].value, tag[i].length); position += tag[i].length;
						}
						if (tag[i].type == 0x0110) {
							Append(response.packet, position, "\x01\x10", 2); position += 2;
							response.packet[position] = (unsigned char) tag[i].length / 256; position++;
							response.packet[position] = (unsigned char) tag[i].length % 256; position++;
							Append(response.packet, position, tag[i].value, tag[i].length); position += tag[i].length;
						}
					}

					response.length = position; 
					return response;
				   	break;

			case PADR: 	// Answer with PADS
					
					// Parse PPPoE Discover tags, i.e. copy all tags to PPPoE_DISCOVER_TAG array
					i = 0;
					while (i < ntohs(discover->length)) {
						// Get TAG_TYPE
						tag[tagNumber].type = discover->tags[i] * 256 + discover->tags[i+1];
		
						// Get TAG_LENGTH
						tag[tagNumber].length = discover->tags[i+2] * 256 + discover->tags[i+3];
						
						// Get TAG_VALUE
						i = i + 4; 
						j = 0;
						bzero(tag[tagNumber].value, MAX_TAG_LENGTH);
						while (j < tag[tagNumber].length) {
							tag[tagNumber].value[j] = discover->tags[i];
							i++; 
							j++;
						}
						
						// If the tags are Service-Name, Host-Uniq tag or Relay-Session-Id, include their size in total tag length
						if ((tag[tagNumber].type == 0x0101) | (tag[tagNumber].type == 0x0103) | (tag[tagNumber].type == 0x0110)) {
							totalTagLength += (tag[tagNumber].length + 4);
						}						

						tagNumber++;
					}
					
					// Create reply packet
					position = 0;
					// Add destination MAC	
					memcpy(response.packet, ethPacket->sourceMAC, MAC_ADDRESS_LENGTH); position += MAC_ADDRESS_LENGTH;
					// Add placeholder for source MAC
					Append(response.packet, position, "\x00\x00\x00\x00\x00\x00", MAC_ADDRESS_LENGTH); position += MAC_ADDRESS_LENGTH;
					// Add ethertype
					Append(response.packet, position, "\x88\x63", ETHERTYPE_LENGTH); position += ETHERTYPE_LENGTH;
					// Add PPPoE header
					Append(response.packet, position, "\x11", 1); position++;
					Append(response.packet, position, "\x65", 1); position++;
					// Generate and add Session_ID
					srand(time(NULL));
					response.packet[position] = rand() / 256; position++;
					response.packet[position] = rand() % 256; position++;
					// Add length
					response.packet[position] = (unsigned char) totalTagLength / 256; position++;
					response.packet[position] = (unsigned char) totalTagLength % 256; position++;
					// Add Service-Name, Host-Uniq tag and Relay-Session-Id, if sent in PADI
					for(i = 0; i < tagNumber; i++) {
						if (tag[i].type == 0x0101) {
							Append(response.packet, position, "\x01\x01", 2); position += 2;
							response.packet[position] = (unsigned char) tag[i].length / 256; position++;
							response.packet[position] = (unsigned char) tag[i].length % 256; position++;
							Append(response.packet, position, tag[i].value, tag[i].length); position += tag[i].length;
						}
						if (tag[i].type == 0x0103) {
							Append(response.packet, position, "\x01\x03", 2); position += 2;
							response.packet[position] = (unsigned char) tag[i].length / 256; position++;
							response.packet[position] = (unsigned char) tag[i].length % 256; position++;
							Append(response.packet, position, tag[i].value, tag[i].length); position += tag[i].length;
						}
						if (tag[i].type == 0x0110) {
							Append(response.packet, position, "\x01\x10", 2); position += 2;
							response.packet[position] = (unsigned char) tag[i].length / 256; position++;
							response.packet[position] = (unsigned char) tag[i].length % 256; position++;
							Append(response.packet, position, tag[i].value, tag[i].length); position += tag[i].length;
						}
					}

					response.length = position; 
					return response;
					break;

			default: 	response.length = 0;
					return response;
		} 
	}
	
	free(ethPacket);
	free(discover);	

	return response;
}
