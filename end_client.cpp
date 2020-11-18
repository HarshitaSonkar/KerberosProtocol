#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <iostream>
#include <cstdlib>
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>
#include<bits/stdc++.h>
#include <cstdio>
#include <string>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <sstream>
#include <netdb.h>
#include "cryptopp/integer.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/osrng.h"
#include "cryptopp/oids.h"
#include "cryptopp/cryptlib.h"
#define ll long int
#include<bits/stdc++.h>
#include<string>
using namespace std;
using namespace CryptoPP;
using CryptoPP::Integer;
using CryptoPP::ModularArithmetic;

string mess(string cipher , ll key)
{
	string t = "";
	for(int i=0;i<cipher.size();i++)
	{
		t+=cipher[i]^key;
	}
	return t;
}
int main(int argc, char *argv[]) {
   //Variables for AS
   int sockfd, portno, n;
   ll keyA;
   AutoSeededRandomPool ra;
   struct sockaddr_in serv_addr;
   struct hostent *server;
   
   //Variables for TGS
   int sockfd1, portno1;
   ll keyTgs;
   ll keyBob;
   string ticketTgs;
   string ticketBob;
   struct sockaddr_in serv_addr1;
   struct hostent *server1;
   //Variables for Bob
   int sockfd2, portno2;
   struct sockaddr_in serv_addr2;
   struct hostent *server2;
   
   char buffer[256];
   
   if (argc < 5) {
      fprintf(stderr,"usage %s hostname port\n", argv[0]);
      exit(0);
   }
//Connection for AS	
   portno = atoi(argv[2]);
   
   /* Create a socket point */
   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   
   if (sockfd < 0) {
      perror("ERROR opening socket");
      exit(1);
   }
	
   server = gethostbyname(argv[1]);
   
   if (server == NULL) {
      fprintf(stderr,"ERROR, no such host\n");
      exit(0);
   }
   
   bzero((char *) &serv_addr, sizeof(serv_addr));
   serv_addr.sin_family = AF_INET;
   bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
   serv_addr.sin_port = htons(portno);
   
   /* Now connect to the server */
   if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
      perror("ERROR connecting");
      exit(1);
   }
//Code start Connection for TGS
   portno1 = atoi(argv[4]);

   /* Create a socket point */
   sockfd1 = socket(AF_INET, SOCK_STREAM, 0);

   if (sockfd1 < 0) {
      perror("ERROR opening socket");
      exit(1);
   }

   server1 = gethostbyname(argv[3]);

   if (server1 == NULL) {
      fprintf(stderr,"ERROR, no such host\n");
      exit(0);
   }

   bzero((char *) &serv_addr1, sizeof(serv_addr1));
   serv_addr1.sin_family = AF_INET;
   bcopy((char *)server1->h_addr, (char *)&serv_addr1.sin_addr.s_addr, server1->h_length);
   serv_addr1.sin_port = htons(portno1);

   /* Now connect to the server */
   if (connect(sockfd1, (struct sockaddr*)&serv_addr1, sizeof(serv_addr1)) < 0) {
      perror("ERROR connecting");
      exit(1);
   }
//Code end Connection for TGS 
//Code start for Connection for Bob
   portno2 = atoi(argv[6]);

   /* Create a socket point */
   sockfd2 = socket(AF_INET, SOCK_STREAM, 0);

   if (sockfd2 < 0) {
      perror("ERROR opening socket");
      exit(1);
   }

   server2 = gethostbyname(argv[5]);

   if (server2 == NULL) {
      fprintf(stderr,"ERROR, no such host\n");
      exit(0);
   }

   bzero((char *) &serv_addr2, sizeof(serv_addr2));
   serv_addr2.sin_family = AF_INET;
   bcopy((char *)server2->h_addr, (char *)&serv_addr2.sin_addr.s_addr, server2->h_length);
   serv_addr2.sin_port = htons(portno2);

   /* Now connect to the server */
   if (connect(sockfd2, (struct sockaddr*)&serv_addr2, sizeof(serv_addr2)) < 0) {
      perror("ERROR connecting");
      exit(1);
   }
//Code end for Connection for Bob
   while(true)
   {
   	cout<<"Enter 1 for key establishment/renewal\nEnter 2 for receiving the TGS session key\nEnter 3 for sending ticket to TGS and getting session key from TGS\nEnter 4 for sending ticket to Resource server and Establishing connection\n";
	char option;
	cin>>option;

	switch(option)
	{
		case '1':
		{
		/*Key Establishment and renewal begins */
		write(sockfd,&option,1);
		bzero(buffer,256);
		read(sockfd, buffer, 255);
		string str(buffer);
		keyA = stoi(str);
		cout<<"Key for Client"<<keyA<<endl;
		/*Key Establishment and renewal begins */ 			
		}
		break;
		case '2':
		{
		/*Receiving TGS session key and Ticket for TGS*/
		write(sockfd,&option,1);
		write(sockfd,"Alice",5);
		bzero(buffer,256);
		read(sockfd, buffer, 255);
		string str(buffer);
		str = mess(str,keyA);
		int comma = str.find(",");
		keyTgs = stoi(str.substr(0,comma));
      cout<<"Session key for TGS"<<keyTgs<<endl;
		ticketTgs = str.substr(comma+1,str.size());
		/*End of Receiving TGS session key and Ticket for TGS*/
		}
		break;
		case '3':
		{
		/*Sending ticket to TGS and getting session key from TGS*/
		string tgsdata="";
		tgsdata += "Bob," + mess("Fresh",keyTgs)+ "," +ticketTgs;
		bzero(buffer,256);
		strcpy(buffer,tgsdata.c_str());
		write(sockfd1,buffer,strlen(buffer));
		bzero(buffer,256);
		read(sockfd1, buffer, 255);
		string str(buffer);
		int comma = str.find(",");
		ticketBob = str.substr(comma+1,str.size());
		str = str.substr(0,comma);
		str = mess(str,keyTgs);
		comma = str.find(",");
		keyBob = stoi(str.substr(comma+1,str.size()));
		/*End of sending ticket to TGS and getting session key from TGS*/
		}
		break;
		case '4':
		{
		/*Sending ticket to Resource server and Establishing connection*/
		string bobdata="";
		bobdata +=mess("Fresh",keyBob)+ "," +ticketBob;
		bzero(buffer,256);
		strcpy(buffer,bobdata.c_str());
		write(sockfd2,buffer,strlen(buffer));
		bzero(buffer,256);
		read(sockfd2, buffer, 255);
		string str(buffer);
		str = mess(str,keyBob);
		if(str.compare("Fresh-1")==0) cout<<"Session is established and secure\n";
		/*End of sending ticket to Resource server and Establishing connection*/
		}
		break;
	}
   }
   

   

   return 0;
}