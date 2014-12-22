#ifndef FUNCTIONS_MYSQL_H_
#define FUNCTIONS_MYSQL_H_

BYTE ConnectToDatabase();
int CheckSubscriberPassword(char *subscriberUsername, char *subscriberPassword, LONG_MAC MAC);
void SetSubscriberStateMAC(LONG_MAC MAC, BYTE *state);
void CreateNewSession(LONG_MAC MAC, IP_ADDRESS IP, unsigned short pppoeSession);
void DeactivateSession(LONG_MAC MAC);
void UpdateSentReceived(LONG_MAC mac);

#endif
