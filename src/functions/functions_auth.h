#ifndef FUNCTIONS_AUTH_H_
#define FUNCTIONS_AUTH_H_

RESPONSE ParseIncoming_Authentication(char packet[PACKET_LENGTH], int bytesReceived);
RESPONSE ParsePAPAuthenticateRequest(ETHERNET_PACKET *ethPacket, int bytesReceived);

#endif
