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
   ll keyATGS;
   ll keyTGS=99999;
   database["Bob"]=99999;
   /* First call to socket() function */
   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   
   if (sockfd < 0) {
      perror("ERROR opening socket");
      exit(1);
   }
   
   /* Initialize socket structure */
   bzero((char *) &serv_addr, sizeof(serv_addr));
 
   portno = 5002;
   
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
         bzero(buffer,256);
         read(newsockfd,buffer,256);
         string tgsdata(buffer);
         int comma = tgsdata.find(",");
         string resource = tgsdata.substr(0,comma);
         tgsdata = tgsdata.substr(comma+1,tgsdata.size());
         comma = tgsdata.find(",");
         string freshness = tgsdata.substr(0,comma);
         tgsdata = tgsdata.substr(comma+1,tgsdata.size());
         tgsdata = mess(tgsdata,keyTGS);
         comma = tgsdata.find(",");
         string user = tgsdata.substr(0,comma);
         cout<<"Session key for the resourse::"<<user<<endl;
         string tgsticket = tgsdata.substr(comma+1,tgsticket.size());
         keyATGS = stoi(tgsticket);
         freshness = mess(freshness,keyATGS);
         if(freshness.compare("Fresh")==0) cout<<"Message is Fresh\n";
         Integer sessionBOB(ra,16);
         ll sessionbob = sessionBOB.ConvertToLong();
         cout<<"Session Key for The resource BOB::"<<sessionbob<<endl;
         string sessionBob = to_string(sessionbob);
         string ticketBOB = mess(user+","+sessionBob,database[resource]);
         string replyback = mess(resource+","+sessionBob,keyATGS);
         replyback=replyback+","+ticketBOB;
         bzero(buffer,256);
         strcpy(buffer,replyback.c_str());
         write(newsockfd,buffer,strlen(buffer));
   }
   return 0;
}