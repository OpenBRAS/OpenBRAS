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

	int i, j = 0, position, auth_ok = 0, totalLength = 0;
	LONG_MAC mac;
	BYTE peer_id_length, passwd_length;
	BYTE *peer_id_username = malloc(MAX_USERNAME_LENGTH);
	BYTE *peer_id_password = malloc(MAX_PASSWORD_LENGTH);

	struct in_addr radiusIp;
	struct sockaddr_in radiusAddr;
	BYTE requestAuth[16], userPass[MAX_USERNAME_LENGTH], encryptedPass[MD5_DIGEST_LENGTH], hash[MAX_ARGUMENT_LENGTH];
	MD5_CTX context;

	RESPONSE response;
	PPPoE_SESSION *session = malloc(bytesReceived - ETH_HEADER_LENGTH);

	memcpy(session, ethPacket->payload, bytesReceived - ETH_HEADER_LENGTH);

	response.length = 0;
	response.packet = malloc(PACKET_LENGTH);
	bzero(response.packet, PACKET_LENGTH);

	// Get customer MAC address
	mac = ((LONG_MAC) ntohs(ethPacket->sourceMAC[0]) << 32) | ((LONG_MAC) ntohs(ethPacket->sourceMAC[1]) << 16) | ((LONG_MAC) ntohs(ethPacket->sourceMAC[2]));

	// Get Peer-ID Username
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

	// If local authentication is use, check password in the database
	if (!radiusAuth) {

		auth_ok = CheckSubscriberPassword(peer_id_username, peer_id_password, mac);

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

	// Otherwise, add non-authenticated subscriber to tree and send a Radius authentication packet

	// Create Radius destination IP address
	inet_aton(Radius_primary, &radiusIp);
	radiusAddr.sin_family = AF_INET;
	radiusAddr.sin_addr.s_addr = radiusIp.s_addr;
	radiusAddr.sin_port = htons(authPort);

	// Create Radius packet
	position = 0;
	// Add Radius code (Access-Request)
	response.packet[position] = ACCESS_REQUEST; position++;
	// Add Radius identifier
	response.packet[position] = 0x00; position++;
	// Add packet length
	totalLength = 2 + 2 + 16 + 2 + strlen(peer_id_username) + 16 + 6;
	response.packet[position] = totalLength / 256; position++;
	response.packet[position] = totalLength % 256; position++;
	// Add Request Authenticator
	srand(time(NULL));
	for (i = 0; i < 16; i++) {
		requestAuth[i] = rand();
		response.packet[position] = requestAuth[i];
		position++;
	}
	// Add username
	response.packet[position] = USER_NAME; position++; // type
	response.packet[position] = 2 + strlen(peer_id_username); position++; // length
	Append(response.packet, position, peer_id_username, strlen(peer_id_username)); position += strlen(peer_id_username); // value

	// Add password
	response.packet[position] = USER_PASSWORD; position++; // type
	response.packet[position] = 0x12; position++; // length
	// Pad password with nulls
	bzero(userPass, MAX_USERNAME_LENGTH);
	memcpy(userPass, peer_id_username, strlen(peer_id_username));
	// Init MD5
	MD5_Init(&context);
	// Create string to be hashed and execute MD5 hashing
	bzero(hash, MAX_ARGUMENT_LENGTH);
	memcpy(hash, Radius_secret, strlen(Radius_secret));
	memcpy(hash + strlen(Radius_secret), requestAuth, 16);
	MD5_Update (&context, hash, strlen(hash));
	MD5_Final (encryptedPass, &context);
	// XOR hash with the user password
	for (j = 0; j < MD5_DIGEST_LENGTH; j++) encryptedPass[j] = encryptedPass[j] ^ userPass[j];
	Append(response.packet, position, encryptedPass, MD5_DIGEST_LENGTH); position += MD5_DIGEST_LENGTH; // value

	// Add NAS-Port
	response.packet[position] = NAS_PORT; position++; // type
	response.packet[position] = 0x04; position++; // length
	response.packet[position] = session->session_id % 256; position++; // value
	response.packet[position] = session->session_id / 256; position++; // value

	response.length = position;

	// Send to Radius server
	if ((sendto(radiusSocket, response.packet, response.length, 0, (struct sockaddr *) &radiusAddr, sizeof(radiusAddr))) == -1) {
		syslog(LOG_NOTICE, "Error sending request to Radius");
	}

	free(peer_id_username);
	free(peer_id_password);

	response.length = 0;
	return response;
}
