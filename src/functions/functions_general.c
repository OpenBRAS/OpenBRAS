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

// Function which sets values of global BRAS parameters
void SetExternVariables(FILE *fd) {

	int i, param_num = 0;
	CONF_PARAMETER *configuration = malloc(MAX_PARAMETERS * sizeof(CONF_PARAMETER));

	// Call extern variables and set their default values
	extern char AC_Name[MAX_ARGUMENT_LENGTH];
	extern int MRU;
	extern char subscriberInterface[MAX_ARGUMENT_LENGTH];
	extern char outgoingInterface[MAX_ARGUMENT_LENGTH];
	extern char radiusInterface[MAX_ARGUMENT_LENGTH];
	extern int echoInterval;
	extern int sessionTimeout;
	extern char chap[MAX_ARGUMENT_LENGTH];
	extern char pap[MAX_ARGUMENT_LENGTH];
	extern char authPriority[MAX_ARGUMENT_LENGTH];
	extern char IPv4[MAX_ARGUMENT_LENGTH];
	extern char IPv4_primaryDNS[MAX_ARGUMENT_LENGTH];
	extern char IPv4_secondaryDNS[MAX_ARGUMENT_LENGTH];
	extern char IPv4_pool[MAX_ARGUMENT_LENGTH];
	extern char NAT[MAX_ARGUMENT_LENGTH];
	extern char IPv6[MAX_ARGUMENT_LENGTH];
	extern char Radius_primary[MAX_ARGUMENT_LENGTH];
	extern char Radius_secondary[MAX_ARGUMENT_LENGTH];
	extern char Radius_secret[MAX_ARGUMENT_LENGTH];
	extern int authPort;
	extern int accPort;
	extern int radiusAuth;

	extern char db_machine[MAX_ARGUMENT_LENGTH];
	extern char db_username[MAX_ARGUMENT_LENGTH];
	extern char db_password[MAX_ARGUMENT_LENGTH];
	extern char db_name[MAX_ARGUMENT_LENGTH];
	extern unsigned short db_port;

	gethostname(AC_Name, MAX_ARGUMENT_LENGTH);
	MRU = 1492;
	echoInterval = 30;
	sessionTimeout = 86400;
	strcpy(chap, "no");
	strcpy(pap, "yes");
	strcpy(authPriority, "pap");
	strcpy(IPv4, "yes");
	strcpy(IPv4_primaryDNS, "8.8.8.8");
	strcpy(IPv4_secondaryDNS, "8.8.4.4");
	strcpy(NAT, "no");
	strcpy(IPv6, "no");

	radiusAuth = 0;
	strcpy(Radius_primary, "127.0.0.1");
	authPort = 1812;
	accPort = 1813;

	strcpy(db_machine, "localhost");
	strcpy(db_username, "admin");
	strcpy(db_password, "admin");
	strcpy(db_name, "OpenBRAS");
	db_port = 0;

	param_num = ParseConfigurationFile(fd, configuration);

	// Set values of extern variables according to data in configuration file
	for (i = 0; i < param_num; i++) {

		if (strcmp(configuration[i].parameter, "AC-Name") == 0) strcpy(AC_Name, configuration[i].value);
		if (strcmp(configuration[i].parameter, "MRU") == 0) MRU = atoi(configuration[i].value);
		if (strcmp(configuration[i].parameter, "Subscriber_interface") == 0) strcpy(subscriberInterface, configuration[i].value);
		if (strcmp(configuration[i].parameter, "Outgoing_interface") == 0) strcpy(outgoingInterface, configuration[i].value);
		if (strcmp(configuration[i].parameter, "Radius_interface") == 0) strcpy(radiusInterface, configuration[i].value);
		if (strcmp(configuration[i].parameter, "LCP_Echo_interval") == 0) echoInterval = atoi(configuration[i].value);
		if (strcmp(configuration[i].parameter, "Session_timeout") == 0) sessionTimeout = atoi(configuration[i].value);
		if (strcmp(configuration[i].parameter, "CHAP") == 0) strcpy(chap, configuration[i].value);
		if (strcmp(configuration[i].parameter, "PAP") == 0) strcpy(pap, configuration[i].value);
		if (strcmp(configuration[i].parameter, "Authentication_priority") == 0) strcpy(authPriority, configuration[i].value);
		if (strcmp(configuration[i].parameter, "IPv4") == 0) strcpy(IPv4, configuration[i].value);
		if (strcmp(configuration[i].parameter, "IPv4_Primary_DNS") == 0) strcpy(IPv4_primaryDNS, configuration[i].value);
		if (strcmp(configuration[i].parameter, "IPv4_Secondary_DNS") == 0) strcpy(IPv4_secondaryDNS, configuration[i].value);
		if (strcmp(configuration[i].parameter, "IPv4_pool") == 0) strcpy(IPv4_pool, configuration[i].value);
		if (strcmp(configuration[i].parameter, "NAT") == 0) strcpy(NAT, configuration[i].value);
		if (strcmp(configuration[i].parameter, "IPv6") == 0) strcpy(IPv6, configuration[i].value);

		if (strcmp(configuration[i].parameter, "Radius_authentication") == 0) radiusAuth = atoi(configuration[i].value);
		if (strcmp(configuration[i].parameter, "Radius_primary") == 0) strcpy(Radius_primary, configuration[i].value);
		if (strcmp(configuration[i].parameter, "Radius_secondary") == 0) strcpy(Radius_secondary, configuration[i].value);
		if (strcmp(configuration[i].parameter, "Radius_secret") == 0) strcpy(Radius_secret, configuration[i].value);
		if (strcmp(configuration[i].parameter, "Authentication_port") == 0) authPort = atoi(configuration[i].value);
		if (strcmp(configuration[i].parameter, "Accounting_port") == 0) accPort = atoi(configuration[i].value);

		if (strcmp(configuration[i].parameter, "Hostname") == 0) strcpy(db_machine, configuration[i].value);
		if (strcmp(configuration[i].parameter, "Username") == 0) strcpy(db_username, configuration[i].value);
		if (strcmp(configuration[i].parameter, "Password") == 0) strcpy(db_password, configuration[i].value);
		if (strcmp(configuration[i].parameter, "Database_name") == 0) strcpy(db_name, configuration[i].value);
		if (strcmp(configuration[i].parameter, "SQL_port") == 0) db_port = atoi(configuration[i].value);
	}
}

// Function which parses the configuration file
// returns: number of configuration parameters
int ParseConfigurationFile(FILE *fd, CONF_PARAMETER *configuration) {

	int i, j, value_present = 0, param_num;
	char line[MAX_LINE_LENGTH], line_clean[MAX_LINE_LENGTH], parameter[MAX_ARGUMENT_LENGTH], value[MAX_ARGUMENT_LENGTH];

	param_num = 0;
	while(fgets(line, MAX_LINE_LENGTH, fd) != NULL) {

		// Ignore comments
		if (line[0] == '#') continue;

		// Remove whitespaces from each configuration line
		i = 0; j = 0;
		while(line[i] != 0) {
			if (line[i] != ' ') {
				line_clean[j] = line[i];
				j++;
			}
			i++;
		}
		line_clean[j] = 0;

		// Get parameter name
		sscanf(line_clean, "%[^=]s", configuration[param_num].parameter);

		// Get parameter value
		i = 0; j = 0; value_present = 0;
		while(line_clean[i] != 0) {
			if (line_clean[i] == '.') {
				value[j] = line_clean[i];
				j++;
			}
			if (line_clean[i] == '/') {
				value[j] = line_clean[i];
				j++;
			}
			if (line_clean[i] < 48) {
				i++;
				continue;
			}
			if (line_clean[i] == '=') {
				value_present = 1;
				i++;
				continue;
			}
			if (value_present) {
				value[j] = line_clean[i];
				j++;
			}
			i++;
		}
		value[j] = 0;

		// If there is no valid value for the parameter, ignore
		if (value[0] < 48) continue;
		else strcpy(configuration[param_num].value, value);

		param_num++;
	}

	return param_num;
}

// Function which appends two strings, ignoring null values
void Append(char *dst, int dstLen, char *src, int srcLen) {
	int i = 0;
	while (i < dstLen) {
		dst++;
		i++;
	}
	i = 0;
	while (i < srcLen) {
		*dst = *src;
		dst++;
		src++;
		i++;
	}
}

// Function which gets the MAC address of selected interface
// returns: MAC address in array format
BYTE *GetMACAddress(char *interface, int rawSocket) {

	BYTE *mac;
	struct ifreq if_mac;
	struct sockaddr_ll sll;

	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);

	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, interface, IFNAMSIZ-1);
	if (ioctl(rawSocket, SIOCGIFHWADDR, &if_mac) < 0) {
		syslog(LOG_ERR, "MAC address of %s not retrieved", interface);
		return NULL;
	}

	mac = malloc(6 * sizeof(BYTE));
	memcpy(mac, if_mac.ifr_hwaddr.sa_data, 6);

	return mac;
}

// Function which creates a raw socket and binds it to a selected interface
// returns: raw socket
int BindRawSocket(char *interface) {

	struct sockaddr_ll sll;
	struct ifreq ifr;

	// Create raw socket
	if ((rawSocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		syslog(LOG_ERR, "Raw Socket not created on interface %s: %s\n", interface, strerror(errno));
		return -1;
	}

	// Get interface based on command line argument
	strncpy((char *)ifr.ifr_name, interface, IFNAMSIZ);
	if((ioctl(rawSocket, SIOCGIFINDEX, &ifr)) == -1) {
		syslog(LOG_ERR, "Raw interface %s not valid: %s\n", interface, strerror(errno));
		return -1;
	}

	// Bind to raw socket
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);
	if (bind(rawSocket, (struct sockaddr *) &sll, sizeof(struct sockaddr_ll)) == -1) {
		syslog(LOG_ERR, "Bind to raw interface %s not valid\n", interface);
		return -1;
	}

	return rawSocket;
}

// Function which creates a raw socket and binds it to a selected Internet-facing interface
// returns: raw socket
int BindRawSocketInternet(char *interface) {

	struct sockaddr_ll sll;
	struct ifreq ifr;

	// Create raw socket
	if ((rawSocketInternet = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		syslog(LOG_ERR, "Raw Socket not created on interface %s: %s\n", interface, strerror(errno));
		return -1;
	}

	// Get interface based on command line argument
	strncpy((char *)ifr.ifr_name, interface, IFNAMSIZ);
	if((ioctl(rawSocketInternet, SIOCGIFINDEX, &ifr)) == -1) {
		syslog(LOG_ERR, "Raw interface %s not valid: %s\n", interface, strerror(errno));
		return -1;
	}

	// Bind to raw socket
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);
	if (bind(rawSocketInternet, (struct sockaddr *) &sll, sizeof(struct sockaddr_ll)) == -1) {
		syslog(LOG_ERR, "Bind to raw interface %s not valid\n", interface);
		return -1;
	}

	return rawSocketInternet;
}

// Function which creates an IP socket
// returns: IP socket
int CreateIPSocket(char *interface) {

	int one = 1;
	struct ifreq ifr;

	// Create socket for IP packets
	if ((ipSocket = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
		syslog(LOG_ERR, "IP Socket not created");
		return -1;
	}

	// Get interface based on command line argument
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy((char *)ifr.ifr_name, interface, IFNAMSIZ);
	if((ioctl(ipSocket, SIOCGIFINDEX, &ifr)) == -1) {
		syslog(LOG_ERR, "IP interface %s not valid: %s", interface, strerror(errno));
		return -1;
	}

	// Set IP_HDRINCL so that the kernel adds the link layer headers
	if (setsockopt (ipSocket, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) == -1) {
		syslog(LOG_ERR, "IP_HDRINCL not set");
		return -1;
	}

	// Enable sending of broadcast packets
	if (setsockopt (ipSocket, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one))==-1) {
		syslog(LOG_ERR, "SO_BROADCAST not set");
		return -1;
	}

	// Bind socket to interface index.
	if (setsockopt (ipSocket, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof (ifr)) < 0) {
		syslog(LOG_ERR, "IP Socket options error");
		return -1;
	}

	return ipSocket;
}

// Function which creates an UDP socket
// returns: UDP socket
int BindUDPSocket(char *interface) {

	int udpSocket;
	struct sockaddr_in sin;
	struct ifreq ifr;

	// Create UDP socket
	if ((udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		syslog(LOG_ERR, "UDP Socket not created");
		return -1;
	}

	// Get interface based on command line argument
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy((char *)ifr.ifr_name, interface, IFNAMSIZ);
	if((ioctl(udpSocket, SIOCGIFINDEX, &ifr)) == -1) {
		syslog(LOG_ERR, "UDP interface %s not valid: %s", interface, strerror(errno));
		return -1;
	}

	// Get IP address of interface
	strncpy((char *)ifr.ifr_name, interface, IFNAMSIZ);
	if((ioctl(udpSocket, SIOCGIFADDR, &ifr)) == -1) {
		syslog(LOG_ERR, "UDP interface %s not valid: %s", interface, strerror(errno));
		return -1;
	}

	// Set UDP source IP and port
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;
	if (bind(udpSocket, (struct sockaddr *) &sin, sizeof(sin)) == -1) {
		syslog(LOG_ERR, "Bind to UDP interface %s not valid: %s", interface, strerror(errno));
		return -1;
	}

	return udpSocket;
}
