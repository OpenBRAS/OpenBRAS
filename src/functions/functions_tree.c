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

// Function which searches the tree for the node to be deleted
void SearchTree(SUBSCRIBER **root, unsigned long mac, SUBSCRIBER **parent, SUBSCRIBER **tmp)
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
void AddSubscriber(SUBSCRIBER **tree, unsigned long mac, MAC_ADDRESS mac_array, IP_ADDRESS ip, unsigned short session_id) {
	
	// If the location of the new node is found, add new subscriber to bottom of tree
	if ((*tree) == NULL) {

		*tree = malloc (sizeof(SUBSCRIBER));
		(*tree)->right = NULL;
		(*tree)->left = NULL;
		
		(*tree)->mac = mac;
		(*tree)->mac_array[0] = mac_array[0];
		(*tree)->mac_array[1] = mac_array[1];
		(*tree)->mac_array[2] = mac_array[2];
		(*tree)->ip = ip;
		(*tree)->session_id = session_id;
		(*tree)->echoReceived = FALSE;
	}

	// Otherwise, search the tree
	else if (mac < (*tree)->mac) AddSubscriber(&(*tree)->left, mac, mac_array, ip, session_id);
	
	else if (mac > (*tree)->mac) AddSubscriber(&(*tree)->right, mac, mac_array, ip, session_id);
}

// Function which prints the binary tree, used only for testing
void PrintSubscribers(SUBSCRIBER *tree) {

	// Print subscribers by increasing MAC address value
	if (tree != NULL) {

		PrintSubscribers(tree->left);
		
		printf("functions_tree: user with MAC address %lu: IP address %d, session_id 0x%04x\n", tree->mac, tree->ip, ntohs(tree->session_id));		

		PrintSubscribers(tree->right);
	}
}

// Function which searches a subscriber with a given MAC address
// returns: found SUBSCRIBER
SUBSCRIBER *FindSubscriberMAC(SUBSCRIBER **tree, unsigned long mac) {

	// Recursively find subscriber in tree
	if ((*tree) == NULL) return NULL;

	else if (mac < (*tree)->mac) FindSubscriberMAC(&((*tree)->left), mac);
	
	else if (mac > (*tree)->mac) FindSubscriberMAC(&((*tree)->right), mac);

	else if (mac == (*tree)->mac) return *tree;
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
}

// Function which sets the threadID of the subscriber's thread
void SetSubscriberThreadID(SUBSCRIBER **tree, unsigned long mac, pthread_t threadID) {

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
void DeleteSubscriber(SUBSCRIBER **tree, unsigned long mac) {
	
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
