#ifndef FUNCTIONS_IPCP_H_
#define FUNCTIONS_IPCP_H_

RESPONSE ParseIncoming_IPCP(char packet[PACKET_LENGTH], int bytesReceived);
RESPONSE SendIPCPConfigureRequest(RESPONSE response);
RESPONSE ParseIPCPConfigureRequest(ETHERNET_PACKET *ethPacket, int bytesReceived);

#endif
