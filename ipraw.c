#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include "./network.h"

int parse_input(char **input, int size)
{
	char option;
	int pcount=0, icount=0;
	if(size%2 != 0) return 1;//incorrect number of inputs
	for(int i=0; i<size; i+=2)
	{
		if( strlen( input[i] ) != 2) return 1;//incorrect input format
		option = input[i][1];//get letter of option;
		switch(option){
			case 'p':
				if(++pcount > 1) return 1;//incorrect input format
				if( (_filter_proto = get_proto(input[i+1])) == -1) return 1;//incorrect proto format
				break;
			case 'i':
				if(++icount > 1) return 1;//incorrect input format
				if(convert_ip(input[i+1])) return 1;//incorrect ip format
				break;
			default:
				return 1;
				break;
		}
	}
	return 0;	
}

/*input -p protocol -i IP*/
int main(int argc, char **argv)
{
	int sockfd, reclen, buflen=10000;
	char buffer[buflen];
	
	if(argc>1)
	{
		if(parse_input(++argv, argc-1))
		{
			fprintf(stderr,"Error - Usage: ./sniff -p [protocol] -i [IP]\n");
			exit(1);
		}
	}

	//create socket
	if ( (sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
	{
		fprintf(stderr,"Error in creating raw socket.\n");
	}
	
	//listen to socket
	while(1)
	{
		reclen = recv(sockfd, buffer, buflen, 0);
		if(reclen > 0)
		{
			dump(buffer, reclen);
		}
	}

	return 0;
}
