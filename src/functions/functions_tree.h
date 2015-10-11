
#ifndef FUNCTIONS_TREE_H_
#define FUNCTIONS_TREE_H_

void AddSubscriber(SUBSCRIBER **tree, BYTE username[MAX_USERNAME_LENGTH], LONG_MAC mac, MAC_ADDRESS mac_array, unsigned short session_id, BYTE authenticator[16]);
void UpdateSubscriber(SUBSCRIBER **tree, LONG_MAC mac, IP_ADDRESS ip);
void PrintSubscribers(SUBSCRIBER *tree);
SUBSCRIBER *FindSubscriberMAC(SUBSCRIBER **tree, LONG_MAC mac);
SUBSCRIBER *FindSubscriberIP(SUBSCRIBER **tree, IP_ADDRESS ip);
void DeleteSubscriber(SUBSCRIBER **tree, LONG_MAC mac);
void SetSubscriberThreadID(SUBSCRIBER **tree, LONG_MAC mac, pthread_t threadID);
SUBSCRIBER *GetSubscriberRadius(SUBSCRIBER **tree, RADIUS_PACKET *radiusData);

#endif
