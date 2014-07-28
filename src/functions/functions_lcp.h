#ifndef FUNCTIONS_LCP_H_
#define FUNCTIONS_LCP_H_

RESPONSE ParseIncoming_LCP(char packet[PACKET_LENGTH], int bytesReceived);
RESPONSE SendTerminateAck(ETHERNET_PACKET *ethPacket, int bytesReceived);
RESPONSE SendTerminateRequest(ETHERNET_PACKET *ethPacket, int bytesReceived);
RESPONSE SendNewConfigureRequest(ETHERNET_PACKET *ethPacket, int bytesReceived);
RESPONSE SendEchoReply(ETHERNET_PACKET *ethPacket, int bytesReceived);
RESPONSE ParseConfigureRequest(ETHERNET_PACKET *ethPacket, int bytesReceived);
RESPONSE SendCodeReject(ETHERNET_PACKET *ethPacket, int bytesReceived);
RESPONSE ParseConfigureNak(ETHERNET_PACKET *ethPacket, int bytesReceived);
RESPONSE SendConfigureRequest(RESPONSE response);

#endif
