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
#include "functions_tree.h"
#include "functions_general.h"
#include "functions_lcp.h"

// Struct received from calling thread
typedef struct {
        LONG_MAC mac;
        int rawSocket;
} THREAD_ARGS;

// Function which sends LCP Terminate-Request and removes user from database
void SendLCPTerminateRequest(SUBSCRIBER *subscriber, int rawSocket, BYTE *mac) {

        int i, j, position = 0;
	LONG_MAC longMAC;
        BYTE *packet = malloc(PACKET_LENGTH);

        // Create Terminate Request
        // Add destination MAC
        for (i = 0; i < 3; i++) {
                packet[position] = subscriber->mac_array[i] % 256; position++;
                packet[position] = subscriber->mac_array[i] / 256; position++;
        }
        // Add source MAC
        for (i = 6, j = 0; i < 12; i++, j++) {
                packet[i] = mac[j]; position++;
        }
        // Add ethertype
        Append(packet, position, "\x88\x64", ETHERTYPE_LENGTH); position += ETHERTYPE_LENGTH;
        // Add PPPoE header
        packet[position] = 0x11; position++;
        packet[position] = 0x00; position++;
        // Add PPPoE SESSION_ID
        packet[position] = subscriber->session_id % 256; position++;
        packet[position] = subscriber->session_id / 256; position++;
        // Add PPPoE payload length
        packet[position] = 0x00; position++;
        packet[position] = 0x06; position++;
        // Add PPP protocol
        packet[position] = 0xc0; position++;
        packet[position] = 0x21; position++;
        // Add PPP code
        packet[position] = 0x05; position++;
        // Add identifier
        packet[position] = rand() % 256; position++;
        // Add PPP length
        packet[position] = 0x00; position++;
        packet[position] = 0x04; position++;

        // Send packet to subscriber
        if ((sendto(rawSocket, packet, position, 0, NULL, sizeof(struct sockaddr_ll))) == -1) {
                syslog(LOG_NOTICE, "Subscriber thread - Raw Send error");
                return;
        }

	// Remove subscriber from tree and update database
	longMAC = ((LONG_MAC)packet[0] << 40) | ((LONG_MAC)packet[1] << 32) | ((LONG_MAC)packet[2] << 24) | ((LONG_MAC)packet[3] << 16) | ((LONG_MAC)packet[4] << 8) | (LONG_MAC)packet[5];
	RemoveSubscriber_LongMAC(longMAC);	

        free(packet);
}

// Function which sends LCP Echo-Request
void SendEchoRequest(SUBSCRIBER *subscriber, int rawSocket, BYTE *mac) {

	int i, j, position = 0;
	BYTE *packet = malloc(PACKET_LENGTH);

	// Create Echo Request
	// Add destination MAC
	for (i = 0; i < 3; i++) {
		packet[position] = subscriber->mac_array[i] % 256; position++;
		packet[position] = subscriber->mac_array[i] / 256; position++;
	}
	// Add source MAC
	for (i = 6, j = 0; i < 12; i++, j++) {
               	packet[i] = mac[j]; position++;           
        }
	// Add ethertype
        Append(packet, position, "\x88\x64", ETHERTYPE_LENGTH); position += ETHERTYPE_LENGTH;
	// Add PPPoE header
	packet[position] = 0x11; position++;
	packet[position] = 0x00; position++;
	// Add PPPoE SESSION_ID
	packet[position] = subscriber->session_id % 256; position++;
	packet[position] = subscriber->session_id / 256; position++;
	// Add PPPoE payload length
	packet[position] = 0x00; position++;
	packet[position] = 0x0a; position++;
	// Add PPP protocol
	packet[position] = 0xc0; position++;
        packet[position] = 0x21; position++;
	// Add PPP code
	packet[position] = 0x09; position++;
	// Add identifier
	packet[position] = rand() % 256; position++;
	// Add PPP length
	packet[position] = 0x00; position++;
	packet[position] = 0x08; position++;
	// Add Magic-Number (last four bytes of subscriber MAC address)
	packet[position] = subscriber->mac_array[1] % 256; position++;
	packet[position] = subscriber->mac_array[1] / 256; position++;
	packet[position] = subscriber->mac_array[2] % 256; position++;
	packet[position] = subscriber->mac_array[2] / 256; position++;

	// Send packet to subscriber
	if ((sendto(rawSocket, packet, position, 0, NULL, sizeof(struct sockaddr_ll))) == -1) {
       		syslog(LOG_NOTICE, "Subscriber thread - Raw Send error");
               	return;
        }	

	free(packet);
}

// Main thread function which checks if the subscriber replies to LCP Echo-Request packets; if not, it deletes the subscriber
void *SubscriberLCPEchoThread(void *args) {

	int i = 0, exitValue = 0;
	pthread_t tmp;
	THREAD_ARGS *threadArgs = args;	
	SUBSCRIBER *subscriber;
	BYTE *mac = malloc(6);
	time_t start, current;
	double difference = 0.0;

	time(&start);

	// Get MAC address of subscriber-facing interface
        if ((mac = GetMACAddress(subscriberInterface, threadArgs->rawSocket)) == NULL) {
		syslog(LOG_NOTICE, "Subscriber thread - unable to get MAC address of subscriber-facing interface\n");
		return;
	}

	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

	// Find subscriber based on MAC address and exit if he's not active
	sem_wait(&semaphoreTree);
       	subscriber = FindSubscriberMAC(&subscriberList, threadArgs->mac);
       	sem_post(&semaphoreTree);
	if (subscriber == NULL) {
		pthread_exit(&exitValue);
	}	

	// Set subscriber thread ID in the binary tree
	tmp = pthread_self();
	sem_wait(&semaphoreTree);
        SetSubscriberThreadID(&subscriberList, threadArgs->mac, tmp);
        sem_post(&semaphoreTree);

	// Wait initial echo interval time
	sleep(echoInterval);

	while(1) {

		// Send LCP Echo Request to subscriber
		SendEchoRequest(subscriber, threadArgs->rawSocket, mac);
		
		// Sleep for the time of the echo interval; in each second check if session timeout has expired
		for (i = 0; i < echoInterval; i++) {
			sleep(1);

			// If the session timeout has expired, send LCP Terminate-Request to subscriber and exit thread
			if (sessionTimeout != 0) {
				time(&current);
				difference = difftime(current, start);

				if ( ((int) difference) >= sessionTimeout) {
					SendLCPTerminateRequest(subscriber, threadArgs->rawSocket, mac);
					pthread_exit(&exitValue);
				}
			}
		}

		// At this point, the echo interval has expired so check if the Echo reply has been received
		// If Echo reply has not been received, send LCP Terminate-Request and exit thread
		if (subscriber->echoReceived == FALSE) {
			SendLCPTerminateRequest(subscriber, threadArgs->rawSocket, mac);
                        pthread_exit(&exitValue);
		}
		// Otherwise (Echo reply was received), reset echoReceived flag
		else subscriber->echoReceived = FALSE;
	}

	free(mac);
}
