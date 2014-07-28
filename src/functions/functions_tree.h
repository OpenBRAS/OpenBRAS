
#ifndef FUNCTIONS_TREE_H_
#define FUNCTIONS_TREE_H_

void AddSubscriber(SUBSCRIBER **tree, unsigned long mac, MAC_ADDRESS mac_array, IP_ADDRESS ip, unsigned short session_id);
void PrintSubscribers(SUBSCRIBER *tree);
SUBSCRIBER *FindSubscriberMAC(SUBSCRIBER **tree, unsigned long mac);
SUBSCRIBER *FindSubscriberIP(SUBSCRIBER **tree, IP_ADDRESS ip);
void DeleteSubscriber(SUBSCRIBER **tree, unsigned long mac);
void SetSubscriberThreadID(SUBSCRIBER **tree, unsigned long mac, pthread_t threadID);

#endif
