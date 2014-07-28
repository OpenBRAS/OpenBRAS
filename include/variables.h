// CONSTANTs

// Maximum number of subscribers
#define MAX_SUBSCRIBERS 20000

// Total length of captured packet
#define PACKET_LENGTH 2000
#define PPPoE_PACKET_LENGTH 1492

// Ethernet packet headers
#define MAC_ADDRESS_LENGTH 6
#define ETHERTYPE_LENGTH 2
#define ETH_HEADER_LENGTH MAC_ADDRESS_LENGTH * 2 + ETHERTYPE_LENGTH
#define PPPoE_HEADER_LENGTH 6
#define PPP_HEADER_LENGTH 2

// PPPoE constants
#define VERSION_TYPE 0x11
#define PADI 0x09
#define PADO 0x07
#define PADR 0x19
#define PADS 0x65
#define PADT 0xa7

// PPP constants
#define LCP 0xc021
#define IPCP 0x8021
#define IPV6CP 0x8057
#define PAP 0xc023
#define CHAP 0xc223

// LCP and IPCP constants
#define CONF_REQ 0x01
#define CONF_ACK 0x02
#define CONF_NAK 0x03
#define CONF_REJ 0x04
#define TERM_REQ 0x05
#define TERM_ACK 0x06
#define CODE_REJ 0x07
#define PROT_REJ 0x08
#define ECHO_REQ 0x09
#define ECHO_REP 0x0a
#define DISC_REQ 0x0b
#define IDENTIFICATION 0x0c

// PAP and CHAP constants
#define AUTH_REQ 0x01
#define AUTH_ACK 0x02
#define AUTH_NAK 0x03
#define CHALLENGE 0x01
#define CHAP_RESPONSE 0x02
#define SUCCESS 0x03
#define FAILURE 0x04

// Maximum number of TAGs and maximum length of tag value in PPPoE discover packets
#define MAX_TAG 18 // IANA registry as of April 11th 2014
#define MAX_TAG_LENGTH 1484 - ETH_HEADER_LENGTH - PPPoE_HEADER_LENGTH

// Maximum number of PPP_OPTIONs and maximum length of option value in PPP packets
#define MAX_OPTION 100
#define MAX_OPTION_LENGTH 1484 - ETH_HEADER_LENGTH - PPPoE_HEADER_LENGTH - PPP_HEADER_LENGTH

// Maximum length of PAP/CHAP username and password
#define MAX_AUTH_LENGTH 200

// Configuration file parameters
#define MAX_LINE_LENGTH 1000
#define MAX_ARGUMENT_LENGTH 100
#define MAX_PARAMETERS 100

// CONFIGURATION VARIABLES
char AC_Name[MAX_ARGUMENT_LENGTH];
int MRU;
char subscriberInterface[MAX_ARGUMENT_LENGTH];
char outgoingInterface[MAX_ARGUMENT_LENGTH];
int echoInterval;
int sessionTimeout;
char chap[MAX_ARGUMENT_LENGTH];
char pap[MAX_ARGUMENT_LENGTH];
char authPriority[MAX_ARGUMENT_LENGTH];
char IPv4[MAX_ARGUMENT_LENGTH];
char IPv4_primaryDNS[MAX_ARGUMENT_LENGTH];
char IPv4_secondaryDNS[MAX_ARGUMENT_LENGTH];
char IPv4_pool[MAX_ARGUMENT_LENGTH];
char NAT[MAX_ARGUMENT_LENGTH];
char IPv6[MAX_ARGUMENT_LENGTH];
char Radius_primary[MAX_ARGUMENT_LENGTH];
char Radius_secondary[MAX_ARGUMENT_LENGTH];
int authPort;
int accPort;

// Semaphore
sem_t semaphoreTree;

// TYPEDEFs

// MAC_ADDRESS definition
typedef unsigned short MAC_ADDRESS[3];

// IP_ADDRESS definition
typedef unsigned int IP_ADDRESS;

// 8-bit definitions
typedef unsigned char BYTE;

// 16-bit definitions
typedef unsigned short ETHERTYPE;
typedef unsigned short PPP_PROTOCOL;

// ETHERNET_PACKET definition
typedef struct {
	MAC_ADDRESS destinationMAC;
	MAC_ADDRESS sourceMAC;
	unsigned short ethType;
	char payload[PACKET_LENGTH - ETH_HEADER_LENGTH];
} ETHERNET_PACKET;

// PPPoE_DISCOVER definition
typedef struct {
	BYTE versionType;
	BYTE code;
	unsigned short session_id;
	unsigned short length;
	unsigned char tags[MAX_TAG];
} PPPoE_DISCOVER;	

// PPPoE_SESSION definition
typedef struct {
	BYTE versionType;
	BYTE code;
	unsigned short session_id;
	unsigned short length;
	unsigned short ppp_protocol;
	BYTE ppp_code;
	BYTE ppp_identifier;
	unsigned short ppp_length;
	unsigned char options[PACKET_LENGTH - ETH_HEADER_LENGTH - PPPoE_HEADER_LENGTH - PPP_HEADER_LENGTH];
} PPPoE_SESSION;

// RESPONSE definition
typedef struct {
	unsigned char *packet;
	int length;
} RESPONSE;

// PPPoE Discover tags
typedef struct {
	unsigned short type;
	unsigned short length;
	unsigned char value[MAX_TAG_LENGTH];
} PPPoE_DISCOVER_TAG;

// PPP options
typedef struct {
	BYTE type;
	BYTE length;
	unsigned char value[MAX_OPTION_LENGTH];
	enum {OK, NAK, REJECT} valid;
} PPP_OPTION;

// Configuration parameters
typedef struct {
	char parameter[MAX_ARGUMENT_LENGTH];
	char value[MAX_ARGUMENT_LENGTH];
} CONF_PARAMETER;

// Subscriber parameters
struct subscriber_definition {
	unsigned long mac;
	MAC_ADDRESS mac_array;
	IP_ADDRESS ip;
	unsigned short session_id;
	pthread_t subscriberThread;
	enum {TRUE, FALSE} echoReceived;
	long bytesSent;
	long bytesReceived;

	struct subscriber_definition *left;
	struct subscriber_definition *right;
};
typedef struct subscriber_definition SUBSCRIBER;

// Subscriber list tree
SUBSCRIBER *subscriberList;
