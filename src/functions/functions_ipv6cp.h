#ifndef FUNCTIONS_IPV6CP_H_
#define FUNCTIONS_IPV6CP_H_

RESPONSE ParseIncoming_IPV6CP(char packet[PACKET_LENGTH], int bytesReceived);
RESPONSE SendIPv6CPTerminateRequest(ETHERNET_PACKET *ethPacket, int bytesReceived);
RESPONSE SendIPV6CPTerminateAck(ETHERNET_PACKET *ethPacket, int bytesReceived);

#endif
