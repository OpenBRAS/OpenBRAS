
#ifndef FUNCTIONS_TREE_H_
#define FUNCTIONS_TREE_H_

void AddSubscriber(SUBSCRIBER **tree, LONG_MAC mac, MAC_ADDRESS mac_array, IP_ADDRESS ip, unsigned short session_id);
void PrintSubscribers(SUBSCRIBER *tree);
SUBSCRIBER *FindSubscriberMAC(SUBSCRIBER **tree, LONG_MAC mac);
SUBSCRIBER *FindSubscriberIP(SUBSCRIBER **tree, IP_ADDRESS ip);
void DeleteSubscriber(SUBSCRIBER **tree, LONG_MAC mac);
void SetSubscriberThreadID(SUBSCRIBER **tree, LONG_MAC mac, pthread_t threadID);

#endif
