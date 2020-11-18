#include "cryptopp/integer.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/osrng.h"
#include "cryptopp/oids.h"
#include "cryptopp/cryptlib.h"
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
#include <fstream>
#include<sstream>
#include<bits/stdc++.h>
#include<string>
#include<bits/stdc++.h>
#define ll long int
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
int main( int argc, char *argv[] ) {
   int sockfd, newsockfd, portno, clilen;
   char buffer[256];
   struct sockaddr_in serv_addr, cli_addr;
   int  n;
   unordered_map<string,ll>database;
   AutoSeededRandomPool ra;
   /*Required variables*/
   ll keyA;
   ll keyTGS=99999;
   /* First call to socket() function */
   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   
   if (sockfd < 0) {
      perror("ERROR opening socket");
      exit(1);
   }
   
   /* Initialize socket structure */
   bzero((char *) &serv_addr, sizeof(serv_addr));
 
   portno = 5001;
   
   serv_addr.sin_family = AF_INET;
   serv_addr.sin_addr.s_addr = INADDR_ANY;
   serv_addr.sin_port = htons(portno);
   
   /* Now bind the host address using bind() call.*/
   if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
      perror("ERROR on binding");
      exit(1);
   }
      
   /* Now start listening for the clients, here process will
      * go in sleep mode and will wait for the incoming connection
   */
   
   listen(sockfd,5);
   clilen = sizeof(cli_addr);
   
   /* Accept actual connection from the client */
   newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, (socklen_t *)&clilen);
   
   if (newsockfd < 0) {
      perror("ERROR on accept");
      exit(1);
   }
   while(true)
   {
      char option;
      n = read(newsockfd,&option,1);

      switch(option)
      {
         case '1':
         {
         /*Key Establishment and renewal begins */
         Integer keyB(ra,16);
         keyA = keyB.ConvertToLong();
         database["Alice"] = keyA;
         string keya1 = to_string(keyA);
         bzero(buffer,256);
         strcpy(buffer,keya1.c_str());
         write(newsockfd,buffer,strlen(buffer));
         /*Key Establishment and renewal begins */            
         }
         break;

         case '2':
         {
         /*Sending TGS session key and Ticket for TGS*/
         bzero(buffer,256);
         read(newsockfd,buffer,256);
         string user(buffer);
         Integer sessionTGS(ra,16);
         ll sessiontgs = sessionTGS.ConvertToLong();
         cout<<"SESSION KEY WITH TGS::"<<sessiontgs<<endl;
         string sessionTgs = to_string(sessiontgs);
         string ticketTGS = mess(user+","+sessionTgs,keyTGS);
         sessionTgs+=","+ticketTGS;
         sessionTgs = mess(sessionTgs,database[user]);
         bzero(buffer,256);
         strcpy(buffer,sessionTgs.c_str());
         write(newsockfd,buffer,strlen(buffer));
         /*End of Sending TGS session key and Ticket for TGS */
         }
         break;

      }
   }
   return 0;
}