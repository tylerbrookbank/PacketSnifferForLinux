void frame_decode(u_char **buffer, int *size);
void packet_decode(u_char **buffer, int *size);
void dump(u_char *buffer, int size);
void rawdump(u_char *buffer, int size);
int convert_ip(char *ip);
void tcp_decode(u_char **buffer, int *size);
void udp_decode(u_char **buffer, int *size);
void print_dump(u_char *buffer, int size, char *proto, int layer);
int get_proto(char *proto);
int convert_mac(char *mac);

/*Datalink header*/
typedef struct datalinkhddr_t{
	u_char destMac[6];//destination mac address
	u_char srcMac[6];//source mac address
	u_char ethType[2];//eth type
} dlhddr_t;

/*network header*/
typedef struct iphddr_t{
	u_char version;//header version
	u_char ihl;//ip header length
	u_char dscp;
	u_char ecn;
	u_char totalLength[2];//total packet length
	u_char id[2];//identifier
	u_char flags;
	u_char frameoffset[2];//frameoffset
	u_char ttl;//time to live
	u_char proto;//protocol type
	u_char checkSum[2];//packet checksum
	u_char destIp[4];//destination ip
	u_char srcIp[4];//source IP
} iphddr_t;

/*transport header*/
typedef struct tcphddr_t{
	u_char destPort[2];//destination port
	u_char srcPort[2];//source port
	u_char seqNum[4];//sequence number
	u_char ackNum[2];//acknowledge number
	u_char flags[2];//flags (inc ack/syn/fin wtc.)
	u_char windowSize[2];//windowsize
	u_char checkSum[2];//check sum number
	u_char urgent[2];//urgent flag...?
} tcphddr_t;

typedef struct udphddr_t{
	u_char srcPort[2];//source port
	u_char destPort[2];//destination port
	u_char length[2];//length
	u_char checkSum[2];//check sum
} udphddr_t;

/*protocol numbers*/
#define ICMP 1
#define ARP 2
#define OTHR 3
#define TCP 4
#define UDP 5
#define FALSE 0
#define TRUE 1

/*header structs*/
dlhddr_t datalink;
iphddr_t iphead;
tcphddr_t tcphead;
udphddr_t udphead;

/*flag varibles*/
u_char saved_ip[4];
u_char saved_mac[4];
int protoNum, _filter_proto = FALSE;

/*function to get proto num from*/
int get_proto(char *proto)
{
        if(!strcmp(proto,"ARP"))
                return ARP;
        else if(!strcmp(proto,"ICMP"))
                return ICMP;
        else if(!strcmp(proto,"TCP"))
                return TCP;
        else if(!strcmp(proto,"UDP"))
                return UDP;
        else if(!strcmp(proto,"OTHR"))
                return OTHR;
        else
                return -1;
}

void frame_decode(u_char **buffer, int *size)
{
	/*check to see if buffer is at least 14 bytes
		-the min size of the frame header*/
	if(*size<=14)
	{
		fprintf(stderr, "Frame decode: buffer is incorrect length.\n");
		exit(1);
	}

	/*copy the first 6 bytes of buffer into destMac*/
	memcpy(datalink.destMac, *buffer, 6);
	*buffer += 6;//increase buffer pointer
	
	/*copy the second 6 bytes of buffer into srcMac*/
	memcpy(datalink.srcMac, *buffer, 6);
	*buffer += 6;

	/*copy the next two bytes into eth frame*/
	memcpy(datalink.ethType, *buffer, 2);
	*buffer += 2;

	*size -= 14; //calc remaining bufsize
}

void packet_decode(u_char **buffer, int *size)
{
	if(*size < 2)
	{
		fprintf(stderr, "No network header.\n");
		return;
	}
	/*get version 4 bits*/
	iphead.version = **buffer >> 4;

	/*get ihl 4 bits*/
	iphead.ihl = **buffer & 15;

	if( (int)iphead.ihl < (int)'\x05')
	{
		fprintf(stderr,"Incorrect network header format.\n");
		return;
	}

	/*dscp 6 bits*/
	(*buffer)++;
	iphead.dscp = **buffer >> 2;

	/*ecn 2 bits*/
	iphead.ecn = **buffer & 3;
	
	/*total length 2 bytes*/
	(*buffer)++;
	memcpy(iphead.totalLength, *buffer, 2);
	
	/*id 2 bytes*/
	*buffer += 2;
	memcpy(iphead.id, *buffer, 2);

	/*flags 3 bits*/
	*buffer += 2;
	iphead.flags = **buffer >> 5;

	/*fragmentation offset 13 bits*/
	iphead.frameoffset[0] = **buffer & 31;
	iphead.frameoffset[1] = *(++(*buffer));

	/*ttl 1 byte*/
	(*buffer)++;
	iphead.ttl = *((*buffer)++);

	/*protocol 1  byte*/
	iphead.proto = *((*buffer)++);

	/*header checksum 2 bytes*/
	memcpy(iphead.checkSum, *buffer, 2);

	/*dest ip 4 bytes*/
	*buffer += 2;
	memcpy(iphead.destIp, *buffer, 4);

	/*src ip 4 bytes*/
	*buffer += 4;
	memcpy(iphead.srcIp, *buffer, 4);
	*buffer += 4;

	*buffer += (iphead.ihl * 4) - 20;	
	/*options if ihl > 5*/
	*size -= 20 + ((iphead.ihl * 4) - 20);
}

void tcp_decode(u_char **buffer, int *size)
{
	int dataoffset;
	/*20 bytes*/
	if(*size<20)
	{
		fprintf(stderr, "No TCP header.\n");
		return;
	}
	
	/*source port 2 bytes*/
	memcpy( tcphead.srcPort, *buffer, 2 );
	*buffer += 2;//buffer is packet buffer

	/*dest port 2 bytes*/
	memcpy( tcphead.destPort, *buffer, 2 );
	*buffer += 2;

	/*seq num 4 bytes*/
	memcpy( tcphead.seqNum, *buffer, 4);
	*buffer += 4;

	/*ack num 4 bytes*/
	memcpy ( tcphead.ackNum, *buffer, 4 );
	*buffer += 4;

	/*flags 2 bytes*/
	memcpy( tcphead.flags, *buffer, 2 );
	*buffer += 2;

	/*window size 2 bytes*/
	memcpy( tcphead.windowSize, *buffer, 2 );
	*buffer += 2;

	/*check sum 2 bytes*/
	memcpy( tcphead.checkSum, *buffer, 2 );
	*buffer += 2;
	
	/*urgent 2 bytes*/
	memcpy( tcphead.urgent, *buffer, 2);
	*buffer += 2;
	
	if( (dataoffset = tcphead.flags[0] >> 4) > 5)
		*buffer += dataoffset*4 - 20;
	/*options...*/
	*size -= 20 + ( (tcphead.flags[0] >> 5) * 4 );
}

void udp_decode(u_char **buffer, int *size)
{
	/*udp header 8 bytes*/
	if(*size < 8)
	{
		fprintf(stderr, "No UDP header.\n");
		return;
	}

	/*source port 2*/
	memcpy( udphead.srcPort, *buffer, 2 );
	*buffer += 2;

	/*dest port 2*/
	memcpy( udphead.destPort, *buffer, 2);
	*buffer += 2;

	/*length 2*/
	memcpy( udphead.length, *buffer, 2 );
	*buffer += 2;

	/*check sum 2*/
	memcpy( udphead.checkSum, *buffer, 2 );
	*buffer += 2;
	
	*size -= 8;
}

void print_dump(u_char *buffer, int size, char *proto, int layer)
{
	u_char srcPort[2];
	u_char destPort[2];

	if( layer > 2 && !strcmp(proto,"TCP") )
	{
		memcpy(srcPort, tcphead.srcPort, 2);
		memcpy(destPort, tcphead.destPort, 2);
	}
	else if( layer > 2 )
	{
		memcpy(srcPort, udphead.srcPort, 2);
		memcpy(srcPort, udphead.srcPort, 2);
	}

	printf("\nProtocol: %s - %02x\n", proto,iphead.proto);//careful tyler...   
        printf("Dest Mac: %02x %02x %02x %02x %02x %02x\tSorc Mac: %02x %02x %02x %02x %02x %02x\n",
		datalink.destMac[0],datalink.destMac[1],datalink.destMac[2],datalink.destMac[3],datalink.destMac[4],datalink.destMac[5],
		datalink.srcMac[0],datalink.srcMac[1],datalink.srcMac[2],datalink.srcMac[3],datalink.srcMac[4],datalink.srcMac[5]);
	printf("Dest Ip: %d.%d.%d.%d\t\tSorc IP: %d.%d.%d.%d\n",
		iphead.destIp[0],iphead.destIp[1],iphead.destIp[2],iphead.destIp[3],
		iphead.srcIp[0],iphead.srcIp[1],iphead.srcIp[2],iphead.srcIp[3]);
	if(layer > 2)
	{
		printf("Source Port: %02x %02x\t\tDestination Port: %02x %02x\n",
			srcPort[0], srcPort[1],
			destPort[0], destPort[1]);
	}
	rawdump(buffer, size);
}

void dump(u_char *buffer, int size)
{
	int count = size;
	char proto[4];
	u_char *ptr = buffer;
	
	frame_decode(&ptr, &count);
	if(datalink.ethType[1] == '\x00')
	{
		packet_decode(&ptr, &count);
		if(iphead.proto == '\x01')
		{
			strcpy(proto,"ICMP");
			protoNum = ICMP;
		}
		else if(iphead.proto == '\x06')
		{
			strcpy(proto,"TCP");
			tcp_decode(&ptr, &count);
			/*error check if tcp decode failed*/
			protoNum = TCP;
		}
		else if(iphead.proto == '\x11')
		{
			strcpy(proto,"UDP");
			udp_decode(&ptr, &count);
			protoNum = UDP;
		}
		else
		{
			strcpy(proto,"OTHR");
			protoNum = OTHR;
		}		
	}
	else
	{
		strcpy(proto,"ARP");
		protoNum = ARP;
	}

	if(saved_ip[0] == '\x00' && _filter_proto == FALSE)
	{
		if( protoNum >= TCP )
			print_dump( buffer, size, proto, protoNum );
		else
			print_dump( buffer, size, proto, protoNum );
	}
	else if(_filter_proto == FALSE)
	{
		if(saved_ip[0]==iphead.destIp[0] &&
			saved_ip[1]==iphead.destIp[1] &&
			saved_ip[2]==iphead.destIp[2] &&
			saved_ip[3]==iphead.destIp[3])
		{
			if( protoNum > 1 )
				print_dump( buffer, size, proto, protoNum );
			else
				print_dump( buffer, size, proto, protoNum );
		}
	}
	else if(saved_ip[0] == '\x00')
	{
		if(_filter_proto==protoNum)
                {
                        if( protoNum > 1 )
                                print_dump( buffer, size, proto, protoNum );
                        else
                                print_dump( buffer, size, proto, protoNum );
                }	
	}
	else
	{
		if(_filter_proto==protoNum && 
			saved_ip[0]==iphead.destIp[0] &&
                        saved_ip[1]==iphead.destIp[1] &&
                        saved_ip[2]==iphead.destIp[2] &&
                        saved_ip[3]==iphead.destIp[3])
                {
                        if( protoNum > 1 )
                                print_dump( buffer, size, proto, protoNum );
                        else
                                print_dump( buffer, size, proto, protoNum );
                }

	}
}

/*convert ip returns 0 on success 1 on fail*/
int convert_ip(char *ip)
{
	int counter = 0, tempNum;
	char *token=NULL;
	if(strlen(ip)<1)
	{
		fprintf(stderr,"IP given is incorrect. Cont as if none given.\n");
		return 1;
	}
	token = strtok(ip, ".");
	while(token != NULL)
	{
		counter++;
		if(sscanf(token,"%d",&tempNum) == EOF)
		{
			fprintf(stderr, "IP given is incorrect. Cont as if none given s.\n");
			saved_ip[0]='\x00';
			return 1;
		}
		if(tempNum < 1 || tempNum > 255)
		{
			fprintf(stderr, "IP given is incorrect. Cont as if none given ob.\n");
			saved_ip[0] = '\x00';
			return 1;
		}
		else if(counter>4)
		{
			fprintf(stderr,"IP given is incorrect. Cont as if none given count.\n");
			saved_ip[0] = '\x00';
			return 1;
		}
		else
		{
			saved_ip[counter-1] = tempNum;
			token = strtok(NULL, ".");
		}
	}
	return 0;
}

int convert_mac(char *mac)
{
	return 0;
}

void rawdump(u_char *buffer, int size)
{
	int i, j;
	
	printf("\n",size);
	for(i=0;i<size;i++)
	{
		printf("%02x ", buffer[i]);
		if(i%16==15 || i==size-1)
		{
			for(j=i%16;j<15;j++)
			{
				printf("   ");
			}
			printf(" | ");
			for(j=i-(i%16);j<=i;j++)
			{
				if(buffer[j]>31 && buffer[j]<123) printf("%c",buffer[j]);
				else printf(".");
			}
			printf("\n");
		}
	}
}
