#ifndef FUNCTIONS_GENERAL_H_
#define FUNCTIONS_GENERAL_H_

void SetExternVariables(FILE *fd);
int ParseConfigurationFile(FILE *fd, CONF_PARAMETER *configuration);
void Append(char *dst, int dstLen, char *src, int srcLen);
BYTE *GetMACAddress(char *interface, int rawSocket);
int BindRawSocket(char *interface);
int CreateIPSocket();

#endif
