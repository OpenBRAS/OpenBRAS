/*
Copyright (C) 2015 Branimir Rajtar

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

// Function which searches the tree for the node to be deleted
void SearchTree(SUBSCRIBER **root, LONG_MAC mac, SUBSCRIBER **parent, SUBSCRIBER **tmp)
{
	SUBSCRIBER *tmp2;
	tmp2 = *root ;
	*parent = NULL ;

	while (tmp2 != NULL)
	{
		// If the node to be deleted is found, return
		if (tmp2->mac == mac)
		{
			*tmp = tmp2;
			return;
		}

		*parent = tmp2;

		if (tmp2->mac > mac) tmp2 = tmp2->left;
		else tmp2 = tmp2->right;
	}
}

// Function which adds a subscriber to the tree
void AddSubscriber(SUBSCRIBER **tree, BYTE username[MAX_USERNAME_LENGTH], LONG_MAC mac, MAC_ADDRESS mac_array, unsigned short session_id, BYTE auth_ppp_identifier, BYTE authenticator[16]) {

	// If the location of the new node is found, add new subscriber to bottom of tree
	if ((*tree) == NULL) {

		*tree = malloc (sizeof(SUBSCRIBER));
		(*tree)->right = NULL;
		(*tree)->left = NULL;
		(*tree)->creationTime = time(NULL);

		(*tree)->mac = mac;
		(*tree)->mac_array[0] = mac_array[0];
		(*tree)->mac_array[1] = mac_array[1];
		(*tree)->mac_array[2] = mac_array[2];
		memcpy((*tree)->username, username, strlen(username));
		(*tree)->session_id = session_id;
		(*tree)->echoReceived = FALSE;
		(*tree)->bytesSent = 0;
		(*tree)->bytesReceived = 0;

		(*tree)->authenticated = 0;
		memcpy((*tree)->aaaAuthenticator, authenticator, 16);
		(*tree)->auth_ppp_identifier = auth_ppp_identifier;

		//		PrintSubscribers(*tree);
	}

	// Otherwise, search the tree
	else if (mac < (*tree)->mac) AddSubscriber(&(*tree)->left, username, mac, mac_array, session_id, auth_ppp_identifier, authenticator);

	else if (mac > (*tree)->mac) AddSubscriber(&(*tree)->right, username, mac, mac_array, session_id, auth_ppp_identifier, authenticator);
}

// Function which updates the subscriber to the tree
void UpdateSubscriber(SUBSCRIBER **tree, LONG_MAC mac, IP_ADDRESS ip) {

	// Recursively find subscriber in tree und update it
	if ((*tree) == NULL) return;

	else if (mac < (*tree)->mac) UpdateSubscriber(&((*tree)->left), mac, ip);

	else if (mac > (*tree)->mac) UpdateSubscriber(&((*tree)->right), mac, ip);

	else if (mac == (*tree)->mac) {

		(*tree)->ip = ip;
		(*tree)->authenticated = 1;
	}
}

// Function which prints the binary tree, used only for testing
void PrintSubscribers(SUBSCRIBER *tree) {

	// Print subscribers by increasing MAC address value
	if (tree != NULL) {

		PrintSubscribers(tree->left);

		printf("functions_tree: user with MAC address %llu: IP address %d, session_id 0x%04x\n", tree->mac, tree->ip, ntohs(tree->session_id));

		PrintSubscribers(tree->right);
	}
}

// Function which searches a subscriber with a given MAC address
// returns: found SUBSCRIBER
SUBSCRIBER *FindSubscriberMAC(SUBSCRIBER **tree, LONG_MAC mac) {

	// Recursively find subscriber in tree
	if ((*tree) == NULL) return NULL;

	else if (mac < (*tree)->mac) FindSubscriberMAC(&((*tree)->left), mac);

	else if (mac > (*tree)->mac) FindSubscriberMAC(&((*tree)->right), mac);

	else if (mac == (*tree)->mac) return *tree;

	return NULL;
}

// Function which searches a subscriber with a given IP address
// returns: found SUBSCRIBER
SUBSCRIBER *FindSubscriberIP(SUBSCRIBER **tree, IP_ADDRESS ip) {

	SUBSCRIBER *current, *tmp;

	if ((*tree) == NULL) return NULL;
	current = (*tree);
	while (current != NULL) {
		if (current->left == NULL) {
			if (current->ip == ip) return current;
			current = current->right;
		}
		else {
			tmp = current->left;
			while(tmp->right != NULL && tmp->right != current)
				tmp = tmp->right;
			if(tmp->right == NULL) {
				tmp->right = current;
				current = current->left;
			}
			else {
				tmp->right = NULL;
				if (current->ip == ip) return current;
				current = current->right;
			}
		}
	}

	return NULL;
}

// Function which sets the threadID of the subscriber's thread
void SetSubscriberThreadID(SUBSCRIBER **tree, LONG_MAC mac, pthread_t threadID) {

	// Recursively find subscriber in tree
	if ((*tree) == NULL) return;

	else if (mac < (*tree)->mac) SetSubscriberThreadID(&((*tree)->left), mac, threadID);

	else if (mac > (*tree)->mac) SetSubscriberThreadID(&((*tree)->right), mac, threadID);

	else if (mac == (*tree)->mac) {
		(*tree)->subscriberThread = threadID;
		return;
	}
}

// Function which deletes subscriber from the tree
void DeleteSubscriber(SUBSCRIBER **tree, LONG_MAC mac) {

	SUBSCRIBER *parent, *tmp, *tmpsucc;

	// Return if tree is empty
	if ((*tree) == NULL) return;

	// If the subscriber doesn't exist, return from function
	if (FindSubscriberMAC(tree, mac) == NULL) return;

	// Otherwise find parent of element
	parent = tmp = NULL;
	SearchTree(tree, mac, &parent, &tmp);

	// If the node to be deleted has two children
	if ( (tmp->left != NULL) && (tmp->right != NULL) )
	{
		parent = tmp;
		tmpsucc = tmp->right;

		while (tmpsucc->left != NULL)
		{
			parent = tmpsucc;
			tmpsucc = tmpsucc->left;
		}

		tmp->mac = tmpsucc->mac;
		tmp->ip = tmpsucc->ip;
		tmp->session_id = tmpsucc->session_id;
		tmp = tmpsucc;
	}

	// If the node to be deleted has no children
	if ( (tmp->left == NULL) && (tmp->right == NULL) )
	{
		if (parent == NULL) (*tree) = NULL;
		else if (parent->right == tmp) parent->right = NULL;
		else parent->left = NULL;

		free (tmp);
		return;
	}

	// If the node to be deleted has only rightchild
	if ( (tmp->left == NULL) && (tmp->right != NULL) )
	{
		if (parent == NULL) (*tree) = tmp->right;
		else if (parent->left == tmp) parent->left = tmp->right;
		else parent->right = tmp->right;

		free (tmp);
		return;
	}

	// If the node to be deleted has only left child
	if ( (tmp->left != NULL) && (tmp->right == NULL) )
	{
		if (parent == NULL) (*tree) = tmp->left;
		else if (parent->left == tmp) parent->left = tmp->left;
		else parent->right = tmp->left;

		free (tmp);
		return;
	}
}

// Function which calculates MD5 for comparison with Response Authenticator
void GetSubscriberMD5(BYTE subResponseAuth[MD5_DIGEST_LENGTH], RADIUS_PACKET *aaaData, SUBSCRIBER *sub) {

	int i, j;
	BYTE hash[MAX_ARGUMENT_LENGTH];
	MD5_CTX context;

	// Init MD5
	MD5_Init(&context);
	// Create string to be hashed and execute MD5 hashing
	bzero(hash, MAX_ARGUMENT_LENGTH);
	hash[0] = aaaData->code;
	hash[1] = aaaData->identifier;
	memcpy(hash + 2, (unsigned char *)&aaaData->length, 2);
	memcpy(hash + 4, sub->aaaAuthenticator, 16);
	memcpy(hash + 20, aaaData->options, htons(aaaData->length) - RADIUS_HEADER_LENGTH);
	memcpy(hash + ntohs(aaaData->length), Radius_secret, strlen(Radius_secret));
	MD5_Update (&context, hash, ntohs(aaaData->length) + strlen(Radius_secret));
	MD5_Final (subResponseAuth, &context);

	return;
}

// Function which finds the subscriber to who the Radius message has been sent
SUBSCRIBER *GetSubscriberRadius(SUBSCRIBER **tree, RADIUS_PACKET *radiusData) {

	SUBSCRIBER *current, *tmp;
	BYTE subResponseAuth[16];

	if ( (*tree) == NULL) return NULL;
	current = (*tree);
	while (current != NULL) {
		if (current->left == NULL) {
			GetSubscriberMD5(subResponseAuth, radiusData, current);
			if (!strncmp(subResponseAuth, radiusData->authenticator, 16)) return current;
			current = current->right;
		}
		else {
			tmp = current->left;
			while(tmp->right != NULL && tmp->right != current)
				tmp = tmp->right;
			if(tmp->right == NULL) {
				tmp->right = current;
				current = current->left;
			}
			else {
				tmp->right = NULL;
				GetSubscriberMD5(subResponseAuth, radiusData, current);
				if (!strncmp(subResponseAuth, radiusData->authenticator, 16)) return current;
				current = current->right;
			}
		}
	}

	// not found
	return NULL;
}

// Function that goes through the subscriber tree and deletes users that have not been authenticated for more than 20 seconds
void RefreshTreeOnce(SUBSCRIBER *tree, time_t currentTime) {

#ifdef DEBUG
	CUSTOM_LOG_DATA(LOG_DEBUG,"Enter")
#endif

	// Return if tree is empty
	if ( tree == NULL) return;

	// Check if twenty seconds have expired; delete subscriber if not authenticated
	if ( (difftime(currentTime, tree->creationTime) > 20) && (tree->authenticated == 0)) {
		DeleteSubscriber(&subscriberList, tree->mac);
	}
	if (tree->left != NULL) RefreshTreeOnce(tree->left, currentTime);
	if (tree->right != NULL) RefreshTreeOnce(tree->right, currentTime);
}

// Thread that goes through all subscribers in list and deletes them if they have not been authenticated for more than two seconds.
void *RefreshSubscriberTree(void *args) {

	time_t currentTime;

#ifdef DEBUG
	CUSTOM_LOG_DATA(LOG_DEBUG,"Enter")
#endif

	while (1) {

		sleep(2);
		if (subscriberList == NULL) continue;
		currentTime = time(NULL);

		sem_wait(&semaphoreTree);
		RefreshTreeOnce(subscriberList, currentTime);
		sem_post(&semaphoreTree);
	}
}
