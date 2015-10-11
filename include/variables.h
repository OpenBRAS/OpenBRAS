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
#define RADIUS_HEADER_LENGTH 20

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

// Radius constants
#define ACCESS_REQUEST 0x01
#define ACCESS_ACCEPT 0x02
#define ACCESS_REJECT 0x03

#define USER_NAME 0x01
#define USER_PASSWORD 0x02
#define NAS_PORT 0x05

// Maximum number of TAGs and maximum length of tag value in PPPoE discover packets
#define MAX_TAG 18 // IANA registry as of April 11th 2014
#define MAX_TAG_LENGTH 1484 - ETH_HEADER_LENGTH - PPPoE_HEADER_LENGTH

// Maximum number of PPP_OPTIONs and maximum length of option value in PPP packets
#define MAX_OPTION 100
#define MAX_OPTION_LENGTH 1484 - ETH_HEADER_LENGTH - PPPoE_HEADER_LENGTH - PPP_HEADER_LENGTH

// Maximum length of PAP/CHAP username and password
#define MAX_USERNAME_LENGTH 200
#define MAX_PASSWORD_LENGTH 16

// Configuration file parameters
#define MAX_LINE_LENGTH 1000
#define MAX_ARGUMENT_LENGTH 100
#define MAX_PARAMETERS 100

// CONFIGURATION VARIABLES
char AC_Name[MAX_ARGUMENT_LENGTH];
int MRU;
char subscriberInterface[MAX_ARGUMENT_LENGTH];
char outgoingInterface[MAX_ARGUMENT_LENGTH];
char radiusInterface[MAX_ARGUMENT_LENGTH];
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
int radiusAuth;
char Radius_primary[MAX_ARGUMENT_LENGTH];
char Radius_secondary[MAX_ARGUMENT_LENGTH];
char Radius_secret[MAX_ARGUMENT_LENGTH];
int authPort;
int accPort;

// MySQL VARIABLES
MYSQL *con;
char db_machine[MAX_ARGUMENT_LENGTH];
char db_username[MAX_ARGUMENT_LENGTH];
char db_password[MAX_ARGUMENT_LENGTH];
char db_name[MAX_ARGUMENT_LENGTH];
unsigned short db_port;


// Semaphore
sem_t semaphoreTree;

// TYPEDEFs

// MAC_ADDRESS definition
typedef unsigned short MAC_ADDRESS[3];
typedef unsigned long long LONG_MAC;

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

// RADIUS_PACKET definition
typedef struct {
	BYTE code;
	BYTE identifier;
	unsigned short length;
	BYTE authenticator[16];
	unsigned char options[PACKET_LENGTH - RADIUS_HEADER_LENGTH];
} RADIUS_PACKET;

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
	LONG_MAC mac;
	MAC_ADDRESS mac_array;
	IP_ADDRESS ip;
	BYTE username[MAX_USERNAME_LENGTH];
	unsigned short session_id;
	pthread_t subscriberThread;
	enum {TRUE, FALSE} echoReceived;
	unsigned long long bytesSent;
	unsigned long long bytesReceived;

	BYTE authenticated;
	BYTE aaaAuthenticator[16];
	BYTE auth_ppp_identifier;

	struct subscriber_definition *left;
	struct subscriber_definition *right;
};
typedef struct subscriber_definition SUBSCRIBER;

// Subscriber list tree
SUBSCRIBER *subscriberList;

// Sockets
int rawSocket, ipSocket, rawSocketInternet, radiusSocket;
