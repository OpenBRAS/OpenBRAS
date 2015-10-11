/*
Copyright (C) 2015 Branimir Rajtar

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
#include "functions_radius.h"
#include "functions_tree.h"
#include "functions_general.h"

// Function which receives packets from the Radius server
void *ListenToRadius(void *args) {

	int bytesReceived, position;
	BYTE packet[PACKET_LENGTH], *mac;
	struct sockaddr radiusAddr;
	socklen_t addrlen = sizeof(radiusAddr);
	SUBSCRIBER *sub;

	RADIUS_PACKET *radiusData = malloc(PACKET_LENGTH - RADIUS_HEADER_LENGTH);
	RESPONSE response;
	response.length = 0;
	response.packet = malloc(PACKET_LENGTH);
	bzero(response.packet, PACKET_LENGTH);

	// Get the MAC address of subscriber-facing interface
	if ((mac = GetMACAddress(subscriberInterface, rawSocket)) == NULL) {
		syslog(LOG_ERR, "Unable to get MAC address of Radius-facing interface");
		return NULL;
	}

	// Log start of thread
	syslog(LOG_INFO, "Listening for incoming Radius packets on %s", radiusInterface);

	// Listen to incoming packets from Radius server
	while (1) {

		bzero(packet, PACKET_LENGTH);
		bytesReceived = recvfrom(radiusSocket, &packet, PACKET_LENGTH, 0, &radiusAddr, &addrlen);
		if (bytesReceived == -1) {
			syslog(LOG_NOTICE, "No packets received from the Internet");
			continue;
		}
		memcpy(radiusData, packet, bytesReceived);

		// Discard packets that are not Access-Accept or Access-Reject
		if ( (radiusData->code != ACCESS_ACCEPT) && (radiusData->code != ACCESS_REJECT) ) continue;

		// Find subscriber for who the Radius response is received; if not found, continue
		sem_wait(&semaphoreTree);
		sub = GetSubscriberRadius(&subscriberList, radiusData);
		sem_post(&semaphoreTree);
		if (sub == NULL) continue;

		// Create reply packet for subscriber
		position = 0;
		// Add destination MAC
		memcpy(response.packet, sub->mac_array, MAC_ADDRESS_LENGTH); position += MAC_ADDRESS_LENGTH;
		// Add source MAC
		Append(response.packet, position,  mac, MAC_ADDRESS_LENGTH); position += MAC_ADDRESS_LENGTH;
		// Add ethertype
		Append(response.packet, position, "\x88\x64", ETHERTYPE_LENGTH); position += ETHERTYPE_LENGTH;
		// Add PPPoE header
		Append(response.packet, position, "\x11", 1); position++;
		Append(response.packet, position, "\x00", 1); position++;
		// Add PPPoE SESSION_ID
		response.packet[position] = sub->session_id % 256; position++;
		response.packet[position] = sub->session_id / 256; position++;
		// Add payload length
		if (radiusData->code == ACCESS_ACCEPT)
		{ Append(response.packet, position, "\x00\x07", 2); position += 2; }
		else {
			Append(response.packet, position, "\x00\x0a", 2); position += 2;
		}
		// Add PPP protocol
		Append(response.packet, position, "\xc0\x23", 2); position += 2;
		// Add code for Auth-Ack or Auth-Nak
		if (radiusData->code == ACCESS_ACCEPT)
		{ response.packet[position] = 0x02; position++; }
		else
		{ response.packet[position] = 0x03; position++; }
		// Add identifier
		response.packet[position] = sub->auth_ppp_identifier; position++;
		// Add length
		if (radiusData->code == ACCESS_ACCEPT) {
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
		if (radiusData->code == ACCESS_ACCEPT)
		{
			response.packet[position] = 0x00; position++;
		}
		else {
			Append(response.packet, position, "\x4e\x4f\x4b", 3); position += 3;
		}

		// Send packet to subscriber
		response.length = position;
		if ((sendto(rawSocket, response.packet, response.length, 0, NULL, sizeof(struct sockaddr_ll))) == -1) {
			syslog(LOG_NOTICE, "Error sending response to PPPoE discover message");
		}
	}
}
