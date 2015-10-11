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

// Function which connects to MySQL database
// returns: 0 if connection is ok, -1 otherwise
BYTE ConnectToDatabase() {

	con = mysql_init(NULL);
	if (con == NULL)
	{
		syslog(LOG_ERR, "Connection to database failed: %s", mysql_error(con));
		return -1;
	}

	if (mysql_real_connect(con, db_machine, db_username, db_password, db_name, db_port, NULL, 0) == NULL)
	{
		syslog(LOG_ERR, "Connection to database failed: %s", mysql_error(con));
		mysql_close(con);
		return -1;
	}

	return 0;
}

// Function which updates the number of sent and received bytes of the subscriber
void UpdateSentReceived(LONG_MAC mac) {

	char query[200], sMAC[20], bytesSent[20], bytesReceived[20];
	SUBSCRIBER *sub;

	sprintf(sMAC, "%llu", mac);

	sub = NULL;
	sem_wait(&semaphoreTree);
	sub = FindSubscriberMAC(&subscriberList, mac);
	sem_post(&semaphoreTree);
	if (sub == NULL) {
		printf("null je\n");
		return;
	}

	sprintf(bytesSent, "%llu", sub->bytesSent);
	sprintf(bytesReceived, "%llu", sub->bytesReceived);

	strcpy(query, "UPDATE Sessions SET bytesSent = '");
	strcat(query, bytesSent);
	strcat(query, "', bytesReceived = '");
	strcat(query, bytesReceived);
	strcat(query, "' WHERE subscriberMAC = '");
	strcat(query, sMAC);
	strcat(query, "' ");
	strcat(query, " AND active = 1");

	// Run query
	mysql_query(con, query);
}

// Function that changes the session active flag to zero (i.e. deactivates the session)
void DeactivateSession(LONG_MAC MAC) {

	// Create query
	char query[200], sMAC[20];
	sprintf(sMAC, "%llu", MAC);
	strcpy(query, "UPDATE Sessions SET active = 0 WHERE subscriberMAC = '");
	strcat(query, sMAC);
	strcat(query, "' ");
	strcat(query, " AND active = 1");

	// Run query
	mysql_query(con, query);
}

// Function which creates a new subscriber session in database
void CreateNewSession(LONG_MAC MAC, IP_ADDRESS IP, unsigned short pppoeSession) {

	// Get ID of subscriber with the given MAC address
	char query[200], sMAC[20], sIP[20], sSession[20];
	unsigned short pppoeSession_ntohs;

	sprintf(sMAC, "%llu", MAC);
	sprintf(sIP, "%u", IP);

	pppoeSession_ntohs = ((pppoeSession % 256) * 256) + (pppoeSession / 256);
	sprintf(sSession, "%u", pppoeSession_ntohs);

	strcpy(query, "SELECT IdSubscriber FROM Subscribers WHERE subscriberLastMAC = '");
	strcat(query, sMAC);
	strcat(query, "'");

	mysql_query(con, query);
	MYSQL_RES *result = mysql_store_result(con);
	if (result == NULL) return;

	MYSQL_ROW row;
	row = mysql_fetch_row(result);
	if (row == NULL) return;

	// Insert new subscriber session
	strcpy(query, "INSERT INTO Sessions (idSubscriber, pppoeSession, subscriberMAC, subscriberIP, active) VALUES ('");
	strcat(query, row[0]);
	strcat(query, "', '");
	strcat(query, sSession);
	strcat(query, "', '");
	strcat(query, sMAC);
	strcat(query, "', '");
	strcat(query, sIP);
	strcat(query, "', '1')");

	mysql_query(con, query);
}

// Function which updates subscriber state in the database using the MAC address
void SetSubscriberStateMAC(LONG_MAC MAC, BYTE *state) {

	// Create query
	char query[200], sMAC[20];
	sprintf(sMAC, "%llu", MAC);
	strcpy(query, "UPDATE Subscribers SET subscriberState = '");
	strcat(query, state);
	strcat(query, "' WHERE subscriberLastMAC = '");
	strcat(query, sMAC);
	strcat(query, "'");

	// Run query
	mysql_query(con, query);
}

// Function which updates subscriber state and MAC address in database using the subscriber username
void SetSubscriberState(BYTE *subscriberUsername, BYTE *state, LONG_MAC MAC) {

	// Create query
	char query[200], sMAC[20];
	sprintf(sMAC, "%llu", MAC);
	strcpy(query, "UPDATE Subscribers SET subscriberState = '");
	strcat(query, state);
	strcat(query, "', subscriberLastMAC = '");
	strcat(query, sMAC);
	strcat(query, "' WHERE subscriberUsername = '");
	strcat(query, subscriberUsername);
	strcat(query, "'");

	// Run query
	mysql_query(con, query);
}

// Function which checks whether the provided subscriber's password matches the one in the database
// returns: 1 if ok, zero otherwise
int CheckSubscriberPassword(BYTE *subscriberUsername, BYTE *subscriberPassword, LONG_MAC MAC) {

	// Create query
	char query[200];
	strcpy(query, "SELECT subscriberPassword FROM Subscribers WHERE subscriberUsername = '");
	strcat(query, subscriberUsername);
	strcat(query, "'");

	// Run query
	mysql_query(con, query);
	MYSQL_RES *result = mysql_store_result(con);

	// Check if result matches password
	MYSQL_ROW row;
	row = mysql_fetch_row(result);

	// Return zero if no matching subscriber found
	if (row == NULL) return 0;

	// If zero is returned, the passwords match - update database state and return non-zero
	if (!strcmp(subscriberPassword, row[0])) {
		SetSubscriberState(subscriberUsername, "CONFIGURE", MAC);
		return 1;
	}

	return 0;
}
