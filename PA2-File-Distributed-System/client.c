/*
** client.c -- a stream socket client demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <arpa/inet.h>

/*Header for linked list*/
#include<stdbool.h>

/*Header for reading dir*/
#include <dirent.h>

/*Header for md5*/
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <openssl/md5.h>

#include <ctype.h>

#define MAXDATASIZE 100 // max number of bytes we can get at once 

typedef struct{
	char *partname;
	char *content;
}pieces;


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/*------------------------------------------------------------------------
 * main - TCP client for ECHO service
 *------------------------------------------------------------------------
 */
char** dfc();
int md5(char *filename);
char *put(int hash,int server,int servernum,char *filename);
void dfc_read(int fd,char **header,int *len,char **content);
void dfc_write(int fd,char *header,int len,char *content);
char *encrypt(char *filename);

int
main(int argc, char *argv[])
{
	char	*host = "localhost";	/* host to use if none supplied	*/
	//char	*portnum=argv[2];	/* default server port number	*/
	char **ports;

    int	outchars; 
    char buf[MAXDATASIZE];
    char req[MAXDATASIZE];
    char request[MAXDATASIZE];
    char header=NULL;
    int reqlen=0;
    char hv[MAXDATASIZE];	
    //declaration for get
    int i,index;
    int dfs1, dfs2, dfs3, dfs4, numbytes;
    char filerecover[MAXDATASIZE];
    char *getfilename;
    FILE *fp;
    //declaration for dfc_read
    int readlen=0,rlen=0;
    char *read_req=NULL;    
    char *read_header=NULL;

    int hash;
    int parts[5]={1,0,0,0,0};
    char **content = (char**)malloc(sizeof(char*) * 8);
    for(i=0;i<7;i++){
	content[i]=(char *)malloc(MAXDATASIZE);
    }
//declarication for put
    char *filename;
//declarication for encrypt and decrypt
char *encry;
char *decry;

	if( strstr(argv[1],"dfc.conf")!=NULL ){
		ports=dfc();

		//Verify user and passwd

		//GET PORT NUM
		
		strtok(ports[0],"\n");
		strtok(ports[1],"\n");
		strtok(ports[2],"\n");
		strtok(ports[3],"\n");
		strtok(ports[4],"\n");
		strtok(ports[5],"\n");
		//printf("The host is \"%s\"\nThe port is \"%s\"\n",host,ports[0]);
		dfs1 = TCPecho(host,ports[0]);
		dfs2 = TCPecho(host,ports[1]);
		dfs3 = TCPecho(host,ports[2]);
		dfs4 = TCPecho(host,ports[3]);

//verify user and passwd

		dfc_write(dfs1,req,sizeof(ports[4]),ports[4]);
		dfc_write(dfs2,req,sizeof(ports[4]),ports[4]);
		dfc_write(dfs3,req,sizeof(ports[4]),ports[4]);
		dfc_write(dfs4,req,sizeof(ports[4]),ports[4]);

		dfc_write(dfs1,req,sizeof(ports[5]),ports[5]);
		dfc_write(dfs2,req,sizeof(ports[5]),ports[5]);
		dfc_write(dfs3,req,sizeof(ports[5]),ports[5]);
		dfc_write(dfs4,req,sizeof(ports[5]),ports[5]);

		printf("Input a request:\n");
		fgets(req, MAXDATASIZE, stdin);

		req[MAXDATASIZE] = '\0';	/* insure line null-terminated	*/
		printf(">>>Request is:'%s'\n",req);
		outchars = strlen(req);
		dfc_write(dfs1,req,reqlen,request);
		dfc_write(dfs2,req,reqlen,request);
		dfc_write(dfs3,req,reqlen,request);
		dfc_write(dfs4,req,reqlen,request);

		if( strstr(req,"PUT")!=NULL ){
		filename=strtok(req," ");
		filename=strtok(NULL," ");
		filename=strtok(filename,"\n");//printf("filename is '%s'\n",filename);
		hash=md5(filename);
		sprintf(hv,"%d",hash);//printf("hv is %d\n",hash);
		encry=encrypt(filename);
		}//end of put if


//====================================================================================
//Server1
//====================================================================================	
	//LIST
	if( strcmp(req,"LIST\n")==0 ){
		dfc_read(dfs1, &read_header,&readlen,&read_req);
		if(&read_header==NULL||&read_req==NULL){
		perror("socket read failed:\n");
		exit(1);}
		printf("client: received '%s'\n",read_req);
		list(read_req);
	}
	if( strstr(req,"LIST")!=NULL && strstr(req,"/")){
		dfc_read(dfs1, &read_header,&readlen,&read_req);
		if(&read_header==NULL||&read_req==NULL){
		perror("socket read failed:\n");
		exit(1);}
		printf("client: received '%s'\n",read_req);
		list(read_req);
	}
	//GET
	if( strstr(req,"GET")!=NULL ){
		dfc_read(dfs1, &read_header, &readlen,&read_req);
		printf("client: received '%s'\n",read_req);
		index=atoi(read_req);
		

	if(parts[index]==0){
		parts[index]=1;
		dfc_read(dfs1, &read_header, &readlen,&read_req);
		memcpy(content[index],read_req,readlen);
	}
		//content[index-1]='\0';

		dfc_read(dfs1, &read_header, &readlen,&read_req);
		index=atoi(read_req);

	if(parts[index]==0){
		parts[index]=1;
		dfc_read(dfs1, &read_header, &readlen,&read_req);
		memcpy(content[index],read_req,readlen);
	}

		printf("SEE PARTS %d %d %d %d %d\n",parts[0],parts[1],parts[2],parts[3],parts[4]);
	}//end of get if
	//PUT
	if( strstr(req,"PUT")!=NULL ){
		dfc_write(dfs1,req, strlen(hv),hv);
		put(hash,dfs1,1,filename);
	}//end of put if

//====================================================================================
//Server2
//====================================================================================	
	//LIST
	if( strcmp(req,"LIST\n")==0 ){
		dfc_read(dfs2, &read_header,&readlen,&read_req);
		//free(read_req);
		if(&read_header==NULL||&read_req==NULL){
		perror("socket read failed:\n");
		exit(1);}
		printf("client: received '%s'\n",read_req);
		list(read_req);
	}
	if( strstr(req,"LIST")!=NULL && strstr(req,"/")){
		dfc_read(dfs2, &read_header,&readlen,&read_req);
		if(&read_header==NULL||&read_req==NULL){
		perror("socket read failed:\n");
		exit(1);}
		printf("client: received '%s'\n",read_req);
		list(read_req);
	}
	//GET
	if( strstr(req,"GET")!=NULL ){
		dfc_read(dfs2, &read_header, &readlen,&read_req);
		index=atoi(read_req);

	if(parts[index]==0){
		parts[index]=1;
		dfc_read(dfs2, &read_header, &readlen,&read_req);
		memcpy(content[index],read_req,readlen);
	}
		//content[index-1]='\0';

		dfc_read(dfs2, &read_header, &readlen,&read_req);
		index=atoi(read_req);

	if(parts[index]==0){
		parts[index]=1;
		dfc_read(dfs2, &read_header, &readlen,&read_req);
		memcpy(content[index],read_req,readlen);
	}

		printf("SEE PARTS %d %d %d %d %d\n",parts[0],parts[1],parts[2],parts[3],parts[4]);
	}//end of get if
//PUT
	if( strstr(req,"PUT")!=NULL ){
		//printf("filename is '%s'\n",filename);
		dfc_write(dfs2,req, strlen(hv),hv);
		put(hash,dfs2,2,filename);
		//printf("HASH is '%d'\n",hash);
	}//end of put if
//====================================================================================
//Server3
//====================================================================================	
	//LIST
	if( strcmp(req,"LIST\n")==0 ){
		dfc_read(dfs3, &read_header,&readlen,&read_req);
		if(&read_header==NULL||&read_req==NULL){
		perror("socket read failed:\n");
		exit(1);}
		printf("client: received '%s'\n",read_req);
		list(read_req);

	}
	if( strstr(req,"LIST")!=NULL && strstr(req,"/")){
		dfc_read(dfs3, &read_header,&readlen,&read_req);
		if(&read_header==NULL||&read_req==NULL){
		perror("socket read failed:\n");
		exit(1);}
		printf("client: received '%s'\n",read_req);
		list(read_req);
	}
	//GET
	if( strstr(req,"GET")!=NULL ){
		dfc_read(dfs3, &read_header, &readlen,&read_req);
		index=atoi(read_req);
		parts[index]=1;

		dfc_read(dfs3, &read_header, &readlen,&read_req);
		memcpy(content[index],read_req,readlen);
		//content[index-1]='\0';

		dfc_read(dfs3, &read_header, &readlen,&read_req);
		index=atoi(read_req);
		parts[index]=1;

		dfc_read(dfs3, &read_header, &readlen,&read_req);
		memcpy(content[index],read_req,readlen);


		printf("SEE PARTS %d %d %d %d %d\n",parts[0],parts[1],parts[2],parts[3],parts[4]);
	}//end of get if
//PUT
	if( strstr(req,"PUT")!=NULL ){
		//printf("filename is '%s'\n",filename);
		dfc_write(dfs3,req, strlen(hv),hv);
		put(hash,dfs3,3,filename);
	}//end of put if
//====================================================================================
//Server4
//====================================================================================	
	//LIST
	if( strcmp(req,"LIST\n")==0 ){
		dfc_read(dfs4, &read_header,&readlen,&read_req);
		//free(read_header);free(read_req);
		if(&read_header==NULL||&read_req==NULL){
		perror("socket read failed:\n");
		exit(1);}
		printf("client: received '%s'\n",read_req);
		list(read_req);
	}
	if( strstr(req,"LIST")!=NULL && strstr(req,"/")){
		dfc_read(dfs4, &read_header,&readlen,&read_req);
		if(&read_header==NULL||&read_req==NULL){
		perror("socket read failed:\n");
		exit(1);}
		printf("client: received '%s'\n",read_req);
		list(read_req);
	}
	//GET
	if( strstr(req,"GET")!=NULL ){
		dfc_read(dfs4, &read_header, &readlen,&read_req);
		index=atoi(read_req);
		parts[index]=1;

		dfc_read(dfs4, &read_header, &readlen,&read_req);
		memcpy(content[index],read_req,readlen);
		//content[index-1]='\0';

		dfc_read(dfs4, &read_header, &readlen,&read_req);
		index=atoi(read_req);
		parts[index]=1;

		dfc_read(dfs4, &read_header, &readlen,&read_req);
		memcpy(content[index],read_req,readlen);

		printf("SEE PARTS %d %d %d %d %d\n",parts[0],parts[1],parts[2],parts[3],parts[4]);
	}//end of get if

//get collect all parts, combine them together
if( strstr(req,"GET")!=NULL){
	if(parts[1]==1 && parts[2]==1 && parts[3]==1 && parts[4]==1){
		printf("Show all contents: 1)%s\n\n 2)%s\n\n 3)%s\n\n 4)%s\n\n",content[1],content[2],content[3],content[4]);
		strcpy(filerecover,content[1]);
		strcat(filerecover,content[2]);
		strcat(filerecover,content[3]);
		strcat(filerecover,content[4]);
		printf("See the recovery: %s\n",filerecover);
		getfilename=strtok(req," ");
		getfilename=strtok(NULL," ");
		getfilename=strtok(getfilename,"\n");
		fp=fopen(getfilename,"w+");
		fputs(filerecover,fp);
		fclose(fp);
	}else{
		printf("File is incomplete.\n");
	}
}

//decry=encrypt(getfilename);
//printf("SEE ENcrypt and Decrypt %s\n,%s\n",encry,decry);
//PUT
	if( strstr(req,"PUT")!=NULL ){
		//printf("filename is '%s'\n",filename);
		dfc_write(dfs4,req, strlen(hv),hv);
		put(hash,dfs4,4,filename);
	}//end of put if
	
	}//end of dfc.conf if
	close(dfs1);
	close(dfs2);
	close(dfs3);
	close(dfs4);
	free(read_req);
	free(read_header);
	exit(0);
}


/*------------------------------------------------------------------------
 * TCPecho - send input to ECHO service on specified host and print reply
 *------------------------------------------------------------------------
 */
int TCPecho(const char *host, const char *portnum)
{

    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];
    int sockfd, numbytes; 

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;



    if ((rv = getaddrinfo(host,portnum, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("client: socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("client: connect");
            continue;
        }

        break;
    }

    if (p == NULL) {
        //fprintf(stderr, "client: failed to connect\n");
        perror("client: failed to connect\n");
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
            s, sizeof s);
    printf("client: connecting to %s\n", s);

    freeaddrinfo(servinfo); // all done with this structure



	printf("client sending request to server:\n");

    //close(sockfd);
    return sockfd;
}

/*------------------------------------------------------------------------
 * dfc - parse the configuration file
 *------------------------------------------------------------------------
 */
char **dfc(void){

	FILE *fp;
	char *user;
	char *passwd;
	char *port1,*port2,*port3,*port4;
	char *line=NULL;
	size_t len=0;
	ssize_t read;
	char **ports = (char**)malloc(sizeof(char*) * 6);
	char p1[10],p2[10],p3[10],p4[10],p5[10],p6[10];
	int i;

	fp=fopen("dfc.conf","r");
	if(fp==NULL){
		printf("Fialed to read file.\n");
		exit(1);
	}

	while((read=getline(&line,&len,fp)) != -1){
		if(strstr(line,"Username")!=NULL){
			user=strtok(line," ");
			user=strtok(NULL," ");
			strcpy(p5,user);
		}
		if(strstr(line,"Password")!=NULL){
			passwd=strtok(line," ");
			passwd=strtok(NULL," ");
			strcpy(p6,passwd);
		}
		if(strstr(line,"DFS1")!=NULL){
			port1=strtok(line,":");
			port1=strtok(NULL,":");
			strcpy(p1,port1);
		}
		if(strstr(line,"DFS2")!=NULL){
			port2=strtok(line,":");
			port2=strtok(NULL,":");
			strcpy(p2,port2);
		}
		if(strstr(line,"DFS3")!=NULL){
			port3=strtok(line,":");
			port3=strtok(NULL,":");
			strcpy(p3,port3);
		}
		if(strstr(line,"DFS4")!=NULL){
			port4=strtok(line,":");
			port4=strtok(NULL,":");
			strcpy(p4,port4);
		}
		
		//printf("The content is:\n %s\n",line);
	}
	for(i=0;i<6;i++){
	ports[i]=(char *)malloc(10);
	}
	strcpy(ports[0],p1);
	strcpy(ports[1],p2);
	strcpy(ports[2],p3);
	strcpy(ports[3],p4);
	strcpy(ports[4],p5);
	strcpy(ports[5],p6);

	free(line);
	fclose(fp);
	return ports;

}
/*------------------------------------------------------------------------
 * LIST - Get all file names and check complement
 *------------------------------------------------------------------------
 */


struct test_struct
{
    char *val;
    struct test_struct *next;
};

struct test_struct *head = NULL;
struct test_struct *curr = NULL;

struct test_struct* create_list(char *val)
{
    //printf("\n creating list with headnode as [%s]\n",val);
    struct test_struct *ptr = (struct test_struct*)malloc(sizeof(struct test_struct));
    if(NULL == ptr)
    {
        printf("\n Node creation failed \n");
        return NULL;
    }
    ptr->val = val;
    ptr->next = NULL;

    head = curr = ptr;
    return ptr;
}

struct test_struct* add_to_list(char *val, bool add_to_end)
{
    if(NULL == head)
    {
        return (create_list(val));
    }
/*
    if(add_to_end)
        printf("\n Adding node to end of list with value [%s]\n",val);
    else
        printf("\n Adding node to beginning of list with value [%s]\n",val);
*/
    struct test_struct *ptr = (struct test_struct*)malloc(sizeof(struct test_struct));
    if(NULL == ptr)
    {
        printf("\n Node creation failed \n");
        return NULL;
    }
    ptr->val = val;
    ptr->next = NULL;

    if(add_to_end)
    {
        curr->next = ptr;
        curr = ptr;
    }
    else
    {
        ptr->next = head;
        head = ptr;
    }
    return ptr;
}

void print_list(void)
{
    struct test_struct *ptr = head;

    printf("\n -------Printing list Start------- \n");
    while(ptr != NULL)
    {
        printf("\n [%s] \n",ptr->val);
        ptr = ptr->next;
    }
    printf("\n -------Printing list End------- \n");

    return;
}

/*
========================================================
Reading file names
========================================================
*/
int list(char *listname){

	char *token;
	char *buf;
	//parse list here

	token=strtok(listname,"-");
	
	while( token!=NULL ){

	buf=token;
	//printf("BUF is : %s\n",buf);
	add_to_list(buf,true);
     	token = strtok(NULL, "-");
	}


/*searching and deleting*/
	struct test_struct *ptr=head;
	char tmp[20];
	printf("\n -------Printing list Start------- \n");
		while(ptr != NULL){
			struct test_struct *head=ptr;
			char *fnames=head->val;
			int parts[4]={0,0,0,0};
			/*TAKE FILE NAME*/
			fnames=strtok(fnames,".");
			strcpy(tmp,fnames);
			fnames=strtok(NULL,".");
			strcat(tmp,".");
			strcat(tmp,fnames);
			//printf("See here: %s\n",tmp);
		
			ptr=head->next;

/*go through the rest of the list, checking off parts that have filename in them, and removing them from the list.*/
		struct test_struct *tmptr=ptr;
		struct test_struct *prev=NULL;
	//printf("New ptr is:\n%s\n",tmptr->val);

			while(tmptr!=NULL){
				if( strstr(tmptr->val , tmp)!=NULL ){
            				
					if(prev==NULL){
						//printf("FOUND at head\n");
						//printf("The value is:\n%s\n\n",tmptr->val);

						if(strstr(tmptr->val,".1")!=NULL){
						parts[0]=1;
						}
						if(strstr(tmptr->val,".2")!=NULL){
						parts[1]=1;
						}
						if(strstr(tmptr->val,".3")!=NULL){
						parts[2]=1;
						}
						if(strstr(tmptr->val,".4")!=NULL){
						parts[3]=1;
						}

						ptr=tmptr->next;
						head=ptr;
						tmptr = tmptr->next;

						//printf("The cur is:\n%s\n\n",tmptr->val);
					}
/*
						else if(tmptr->next==NULL){
						printf("FOUND at end\n");
						tmptr==prev;tmptr->next=NULL;
					}
*/
						else{
						//printf("FOUND at middle\n");printf("The value is:\n%s\n\n",tmptr->val);
						
						if(strstr(tmptr->val,".1")!=NULL){
						parts[0]=1;
						}
						if(strstr(tmptr->val,".2")!=NULL){
						parts[1]=1;
						}
						if(strstr(tmptr->val,".3")!=NULL){
						parts[2]=1;
						}
						if(strstr(tmptr->val,".4")!=NULL){
						parts[3]=1;
						}

						prev->next = tmptr->next;
						tmptr = tmptr->next;

					}
        			}else{
					if(prev==NULL){
						//printf("NOT FOUND at head\n");printf("The value is:\n%s\n\n",tmptr->val);
						ptr=tmptr;
						head=ptr;
						prev=tmptr;
						tmptr=tmptr->next; 
					}else{
						//printf("NOT FOUND at middle\n");printf("The value is:\n%s\n\n",tmptr->val);
						prev = tmptr;
            					tmptr = tmptr->next; 
					}			
					
        			}//end of else(not found)
			}//end of inner while loop
			//print_list();

			//printf(">>See parts:%d %d %d %d\n",parts[0],parts[1],parts[2],parts[3]);
			if(parts[0]==1&&parts[1]==1&&parts[2]==1&&parts[3]==1){
				printf("%s\n",tmp);
			}else{
				printf("%s [incomplete]\n",tmp);
			}

    		}//end of outer while loop
    	printf("\n -------Printing list End------- \n");

	free(ptr);
	free(head);
	return 0;

}
/*
========================================================
HASH MD5
========================================================
*/

unsigned char result[MD5_DIGEST_LENGTH];

// Print the MD5 sum as hex-digits.
void print_md5_sum(unsigned char* md) {
    int i;
    for(i=0; i <MD5_DIGEST_LENGTH; i++) {
            printf("%02x",md[i]);
    }
}

// Get the size of the file by its file descriptor
unsigned long get_size_by_fd(int fd) {
    struct stat statbuf;
    if(fstat(fd, &statbuf) < 0) exit(-1);
    return statbuf.st_size;
}

int decimal( unsigned char hex)
{
        int val=0;
        if(isalpha(hex)){
                val = (toupper(hex) - 'A') + 10;
        }else{
                val = hex - '0';
        }
        return val;
}


int md5(char *filename) {
    int file_descript;
    unsigned long file_size;
    char* file_buffer;
    int i;


    file_descript = open(filename, O_RDONLY);
    if(file_descript < 0) exit(-1);

    file_size = get_size_by_fd(file_descript);
    printf("file size:\t%lu\n", file_size);

    file_buffer = mmap(0, file_size, PROT_READ, MAP_SHARED, file_descript, 0);
    MD5((unsigned char*) file_buffer, file_size, result);
    munmap(file_buffer, file_size); 

    print_md5_sum(result);
    printf("  %s\n", filename);


	//char dec[40];
	int mod=0;

    for(i=0;i<16;i++){	
    	//dec[i]=decimal(result[i]);
	//printf("The value of hex is:%d\n",result[i]);
	//printf("The value of dec is:%d\n",dec[i]);
    	mod=(mod*16+result[i])%4;
	//printf("The %d value of x is : %d\n",i,mod);
    }


    return mod;

}

/*
========================================================
PUT-split file and upload
========================================================
*/

char *put(int hash,int server,int servernum,char *filename){

//split the file
	FILE *fp;
	char buf[1024];
	int len,perlen,i;
	char **parts = (char**)malloc(sizeof(char*) * 4);

	for(i=0;i<4;i++){
	parts[i]=(char *)malloc(10000);
	}

	char req[MAXDATASIZE];
	strcpy(req,"PUT");

	fp=fopen(filename,"r");
	if(fp==NULL){
		printf("Fialed to read file.\n");
		exit(1);
	}	

	fseek(fp,0,SEEK_END);	
	len=ftell(fp);
	rewind(fp);

//get length of each part
	perlen=len/4;
	
	for(i=0;i<4;i++){
	fread(buf,perlen,1,fp);
	strcpy(parts[i],buf);
	printf("The content in this part is:\n%s\n\n",parts[i]);

	}
	fclose(fp);
printf("Hash is %d\nServernum is %d\n",hash,servernum);
	if(hash==0){
		if(servernum==1){
		dfc_write(server,req, perlen,parts[0]);
		dfc_write(server,req, perlen,parts[1]);
		}
		if(servernum==2){
		dfc_write(server,req, perlen,parts[1]);
		dfc_write(server,req, perlen,parts[2]);
		}		
		if(servernum==3){
		dfc_write(server,req, perlen,parts[2]);
		dfc_write(server,req, perlen,parts[3]);
		}
		if(servernum==4){
		dfc_write(server,req, perlen,parts[3]);
		dfc_write(server,req, perlen,parts[0]);
		}
	}

	if(hash==1){
		if(servernum==1){
		dfc_write(server,req, perlen,parts[3]);
		dfc_write(server,req, perlen,parts[0]);
		}
		if(servernum==2){
		dfc_write(server,req, perlen,parts[0]);
		dfc_write(server,req, perlen,parts[1]);
		}		
		if(servernum==3){
		dfc_write(server,req, perlen,parts[1]);
		dfc_write(server,req, perlen,parts[2]);
		}
		if(servernum==4){
		dfc_write(server,req, perlen,parts[2]);
		dfc_write(server,req,perlen,parts[3]);
		}
	}

	if(hash==2){
		if(servernum==1){
		dfc_write(server,req, perlen,parts[2]);
		dfc_write(server,req, perlen,parts[3]);
		}
		if(servernum==2){
		dfc_write(server,req, perlen,parts[3]);
		dfc_write(server,req, perlen,parts[0]);
		}		
		if(servernum==3){
		dfc_write(server,req, perlen,parts[0]);
		dfc_write(server,req, perlen,parts[1]);
		}
		if(servernum==4){
		dfc_write(server,req, perlen,parts[1]);
		dfc_write(server,req, perlen,parts[2]);
		}
	}

	if(hash==3){
		if(servernum==1){
		dfc_write(server,req, perlen,parts[1]);
		dfc_write(server,req, perlen,parts[2]);
		}
		if(servernum==2){
		dfc_write(server,req, perlen,parts[2]);
		dfc_write(server,req, perlen,parts[3]);
		}		
		if(servernum==3){
		dfc_write(server,req, perlen,parts[3]);
		dfc_write(server,req, perlen,parts[0]);
		}
		if(servernum==4){
		dfc_write(server,req, perlen,parts[0]);
		dfc_write(server,req, perlen,parts[1]);
		}
	}	

	return 0;
}
/*------------------------------------------------------------------------
 * dfc_write---sending information
 *------------------------------------------------------------------------
 */
void dfc_write(int fd,char *header,int len,char *content){
	
	int hlen=strlen(header);

	if( write(fd, header, hlen + 1)<0 ){
	exit(1);
	}

	if( write(fd,&len,sizeof(len))<0 ){
	exit(1);
	}

	if( write(fd,content,len)<0 ){
	exit(1);
	}
}
/*------------------------------------------------------------------------
 * dfc_read---receiving information
 *------------------------------------------------------------------------
 */
#define MAXDATA 1024

void dfc_read(int fd,char **header,int *len,char **content){
	
	int i;
	int numbytes;
	*header=malloc(MAXDATA);


	for(i=0;i<MAXDATA;i++){
		if((numbytes=read(fd,(*header) + i,1))==-1){
			printf("socket read failed:\n");
			exit(1);
		}
		if((*header)[i] == '\0') break;
	}
	if( (numbytes=read(fd,len,4))==-1 ){
		perror("socket read failed:\n");
		exit(1);
	}
	printf("LENG: %d\n",*len);
	*content = malloc(*len);
	//printf("CONTENT: %s\n",*content);
	if( (numbytes=read(fd,*content,*len))==-1){printf("F3\n");
		perror("socket read failed:\n");
		exit(1);
	}
}
/*------------------------------------------------------------------------
 * encryption---using hash md5
 *------------------------------------------------------------------------
 */
char *encrypt(char *filename) {
    int file_descript;
    unsigned long file_size;
    char* file_buffer;
    int i;
    char *fname;

    file_descript = open(filename, O_RDONLY);
    if(file_descript < 0) exit(-1);

    file_size = get_size_by_fd(file_descript);
    printf("file size:\t%lu\n", file_size);

    file_buffer = mmap(0, file_size, PROT_READ, MAP_SHARED, file_descript, 0);
    MD5((unsigned char*) file_buffer, file_size, result);
    munmap(file_buffer, file_size); 

    print_md5_sum(result);
    
    return result;

}
