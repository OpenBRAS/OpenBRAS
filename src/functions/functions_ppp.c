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
#include "functions_ppp.h"
#include "functions_lcp.h"
#include "functions_auth.h"
#include "functions_ipcp.h"
#include "functions_ipv6cp.h"

// Function which parses incoming PPP Session packets
// returns: PPP response
RESPONSE ParseIncoming_Session(char packet[PACKET_LENGTH], int bytesReceived) {

	RESPONSE response;
	PPPoE_SESSION *session = malloc(bytesReceived - ETH_HEADER_LENGTH);

	ETHERNET_PACKET *ethPacket = malloc(bytesReceived);
	memcpy(ethPacket, packet, bytesReceived);

	response.length = 0;
	response.packet = malloc(PACKET_LENGTH);
	bzero(response.packet, PACKET_LENGTH);
	
	// If the Ethertype is session
	if (!(htons(ethPacket->ethType) ^ ETH_P_PPP_SES)) {
		memcpy(session, ethPacket->payload, bytesReceived - ETH_HEADER_LENGTH);
		
		// If the version-type field is not 0x11 and code field is not 0x00, it's an unvalid PPPoE packet, don't reply
		if ( (session->versionType ^ 0x11) | (session->code ^ 0x00) ) {
			return response;
		}
	
		// If the PPP lenght value is unvalid, don't reply	
		if ( (ntohs(session->ppp_length) < 0) || (ntohs(session->ppp_length) > PPPoE_PACKET_LENGTH) ) {
			response.length = 0;
			return response;
		}

		switch (ntohs(session->ppp_protocol)) {

			case LCP:	// Parse incoming LCP packet
					
					return ParseIncoming_LCP(packet, bytesReceived);
					break;

			case IPCP:	// Parse incoming IPCP packet
					
					return ParseIncoming_IPCP(packet, bytesReceived);
					break;

			case IPV6CP:	// Parse incoming IPV6CP packet
					
					return ParseIncoming_IPV6CP(packet, bytesReceived);
					break;

			case PAP:	// Parse incoming Authentication packet
			case CHAP:	
					return ParseIncoming_Authentication(packet, bytesReceived);
					break;

			default: 
					return response;
		}
	}

	free(ethPacket);
        free(session);

	return response;

}
