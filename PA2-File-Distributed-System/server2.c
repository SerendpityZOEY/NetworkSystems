/*
** server.c -- a stream socket server demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>


/*Header for reading dir*/
#include <sys/types.h>
#include <dirent.h>
#include <string.h>

/*Header for crearte dir*/
#include <sys/stat.h>


#define BACKLOG 10     // how many pending connections queue will hold

#define MAXDATASIZE 100000 // max number of bytes we can get at once 

typedef struct{
	char *partname;
	char *content;
}pieces;

//for ws.conf
typedef struct{
	char *username;
	char *password;
}dfslist;

void sigchld_handler(int s)
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

    while(waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

pieces *get(char *server,char *fname,char *user);
char *list(char *user);
dfslist *dfs(void);
void dfs_read(int fd,char **header,int *len,char **content);
void dfs_write(int fd,char *header,int len,char *content);
void put(char * dir,int server,char *filename,int hash,char *user);
void createdir(char *name,char *server);
void createsubfolder(char *name,char *server,char *subfolder);

int main(int argc, char *argv[])
{
    int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; // connector's address information
    socklen_t sin_size;
    struct sigaction sa;
    int yes=1;
    char s[INET6_ADDRSTRLEN];
    int rv;
    char buf[MAXDATASIZE];

    int numbytes,outchars;
    pieces *getparts;
    int i;
    int reqlen=0,len;
    char *request=NULL;    
    char *header=NULL;

    char *filelist;
//declarication for put func
    int hash;
    char *filename,*filename1;

//declarication for list func
    char listbuf[MAXDATASIZE];
//declarication for ws conf
dfslist *ws;
char user[20];
char passwd[20];
int Found=0;

//declarication for subfolder
char *foldername;
char *subtoken,*subtoken1;
char subbuf[MAXDATASIZE],subbuffer[MAXDATASIZE];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP


    if ((rv = getaddrinfo(NULL, argv[2], &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo); // all done with this structure

    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    printf("server: waiting for connections...\n");

    while(1) {  // main accept() loop
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);
        printf("server%s: got connection from %s\n",argv[1], s);

/*verify user and password*/
	dfs_read(new_fd,&header,&reqlen,&request);
	strcpy(user,request);
	dfs_read(new_fd,&header,&reqlen,&request);
	strcpy(passwd,request);
	ws=dfs();
/*
printf(">>>'%s'\n",ws[0].username);
printf(">>>'%s'\n",ws[1].username);
printf(">>>'%s'\n",ws[0].password);
printf(">>>'%s'\n",ws[1].password);
*/
	if(strcmp(ws[0].username,user)==0){
		if(strcmp(ws[0].password,passwd)==0){
		Found=1;
		}
	}	
	if(strcmp(ws[1].username,user)==0){
		if(strcmp(ws[1].password,passwd)==0){
		Found=1;
		}
	}
//printf(">>'%s'\n",user);
//printf(">>'%s'\n",passwd);
//printf(">>%d\n",Found);
	if(Found==0){
		printf("Invalid Username/Password. Please try again.");
		exit(1);close(new_fd);
	}

        if (!fork() && Found==1) { // this is the child process
            close(sockfd); // child doesn't need the listener

//create dir for user here
	createdir(user,argv[1]);

//read request
	dfs_read(new_fd,&header,&reqlen,&request);
	//printf("HEADER: %s\n", header);
	strcpy(buf,header);

		if(strstr(buf,"GET")!=NULL && strstr(buf,"/")==NULL){
			strtok(buf,"\n");printf("CHECK: buf'%s'\nuser%s\n",buf,user);
			getparts=get(argv[1],buf,user);
			//printf("CUR SERVER IS %s\n",argv[1]);
/*
printf("PART: %s\n",getparts[0].partname);
printf("PART: %s\n",getparts[1].partname);
printf("PART: %s\n",getparts[0].content);
printf("PART: %s\n",getparts[1].content);
*/
	if(strlen(getparts[0].partname)!=0){
		printf("Sending '%s'\n",getparts[0].partname);
			dfs_write(new_fd,buf,strlen(getparts[0].partname),getparts[0].partname);
	}
	if(strlen(getparts[0].content)!=0){
		printf("Sending '%s'\n",getparts[0].content);
			dfs_write(new_fd,buf,strlen(getparts[0].content),getparts[0].content);
	}
	if(strlen(getparts[1].partname)!=0){
		printf("Sending '%s'\n",getparts[1].partname);
			dfs_write(new_fd,buf,strlen(getparts[1].partname),getparts[1].partname);
	}
	if(strlen(getparts[1].content)!=0){
		printf("Sending '%s'\n",getparts[1].content);
			dfs_write(new_fd,buf,strlen(getparts[1].content),getparts[1].content);
	}		
		}//end of compare GET

		if(strstr(buf,"PUT")!=NULL&& strstr(buf,"/")==NULL){
			dfs_read(new_fd,&header,&reqlen,&request);//printf("REQ %s\n",request);
			hash=atoi(request);//printf("HASH %d\n",hash);
			free(request);
			filename=strtok(buf,"\n");
			filename=strtok(filename," ");
			filename=strtok(NULL," ");//printf("FILE '%s'\n",filename);printf("DIR IS %s\n",argv[1]);
			put(argv[1],new_fd,filename,hash,user);
		}
		if(strstr(buf,"LIST")!=NULL&& strstr(buf,"/")==NULL){
			filelist=list(user);
			strcpy(listbuf,filelist);		
			listbuf[MAXDATASIZE] = '\0';	/* insure line null-terminated	*/
			outchars = strlen(listbuf);
			dfs_write(new_fd,buf,outchars+1,listbuf);			
		}

//subfolder

	if(strstr(buf,"GET")!=NULL && strstr(buf,"/")!=NULL){

		memcpy(subbuf,buf,strlen(buf)+1);
		subtoken=strtok(buf," ");
		
		while( subtoken!=NULL ){
			foldername=subtoken;
      			subtoken = strtok(NULL, " ");
		}
			foldername=strdup(foldername);

		foldername=strtok(foldername,"\n");
//======================Implement under subfolder=====================================
			strtok(buf,"\n");
			strcat(user,"/");
			strtok(foldername,"/");
			strcat(user,foldername);
			subtoken1=strtok(subbuf," ");
			subtoken1=strtok(NULL," ");
			strcat(buf," ");
			strcat(buf,subtoken1);
printf("CHECK '%s'\nUser %s\n",buf,user);
			getparts=get(argv[1],buf,user);

printf("PART: %s\n",getparts[0].partname);
printf("PART: %s\n",getparts[1].partname);
printf("PART: %s\n",getparts[0].content);
printf("PART: %s\n",getparts[1].content);


	if(strlen(getparts[0].partname)!=0){
		printf("Sending '%s'\n",getparts[0].partname);
			dfs_write(new_fd,buf,strlen(getparts[0].partname),getparts[0].partname);
	}
	if(strlen(getparts[0].content)!=0){
		printf("Sending '%s'\n",getparts[0].content);
			dfs_write(new_fd,buf,strlen(getparts[0].content),getparts[0].content);
	}
	if(strlen(getparts[1].partname)!=0){
		printf("Sending '%s'\n",getparts[1].partname);
			dfs_write(new_fd,buf,strlen(getparts[1].partname),getparts[1].partname);
	}
	if(strlen(getparts[1].content)!=0){
		printf("Sending '%s'\n",getparts[1].content);
			dfs_write(new_fd,buf,strlen(getparts[1].content),getparts[1].content);
	}		
		
	}//end of get subfolder

	if(strstr(buf,"PUT")!=NULL && strstr(buf,"/")!=NULL){
		memcpy(subbuf,buf,strlen(buf)+1);
		subtoken=strtok(buf," ");
		
		while( subtoken!=NULL ){
			foldername=subtoken;
      			subtoken = strtok(NULL, " ");
		}
			foldername=strdup(foldername);

		foldername=strtok(foldername,"\n");
		createsubfolder(user,argv[1],foldername);
//======================Implement under subfolder=====================================

		dfs_read(new_fd,&header,&reqlen,&request);
		hash=atoi(request);
		free(request);
		filename=strtok(subbuf,"\n");
		filename=strtok(filename," ");
		filename=strtok(NULL," ");strtok(foldername,"/");
		strcat(user,"/");
		strcat(user,foldername);
		put(argv[1],new_fd,filename,hash,user);
	}

	if(strstr(buf,"LIST")!=NULL && strstr(buf,"/")!=NULL){

		foldername=strtok(buf," ");

		foldername=strtok(NULL," ");
		foldername=strtok(foldername,"\n");//printf("FOLDERNAME %s\n",foldername);
		//createsubfolder(user,argv[1],foldername);
//======================Implement under subfolder=====================================
		strtok(foldername,"/");
		strcat(user,"/");
		strcat(user,foldername);//printf("USER %s\n",user);
		filelist=list(user);
		strcpy(listbuf,filelist);		
		listbuf[MAXDATASIZE] = '\0';	/* insure line null-terminated	*/
		outchars = strlen(listbuf);
		dfs_write(new_fd,buf,outchars+1,listbuf);	
		
	}


	
        close(new_fd);
	exit(0);
        }//end of fork
        close(new_fd);  // parent doesn't need this
    }//end of outer while

    free(header);
    free(request);
    return 0;
}
/*------------------------------------------------------------------------
 * dfs_write---sending information
 *------------------------------------------------------------------------
 */
void dfs_write(int fd,char *header,int len,char *content){
	
	int hlen=strlen(header);

	if( write(fd, header, hlen + 1)<0 ){printf("F\n");
	exit(1);
	}else{
	printf("S\n");
	}

	if( write(fd,&len,sizeof(len))<0 ){printf("F\n");
	exit(1);
	}else{
	printf("S\n");
	}

	if( write(fd,content,len)<0 ){printf("F\n");
	exit(1);
	}else{
	printf("S\n");
	}
}
/*------------------------------------------------------------------------
 * dfs_read---receiving information
 *------------------------------------------------------------------------
 */
#define MAXDATA 1024

void dfs_read(int fd,char **header,int *len,char **content){
	
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
	*content = malloc(*len);
	if( (numbytes=read(fd,*content,*len))==-1){printf("F3\n");
		perror("socket read failed:\n");
		exit(1);
	}
}
/*------------------------------------------------------------------------
 * get - download file pieces
 *------------------------------------------------------------------------
 */
pieces *get(char *server,char *fname,char *user){

struct dirent *sd;
int count=0;
DIR *dir;
char filename[10],fpath[10];
//pieces parts[2];
pieces *parts = malloc(sizeof(char*) * 8);
char *token;
FILE *fp;
int len;

/*parse the command*/
fname=strtok(fname," ");
fname=strtok(NULL," ");

strcat(server,"/");
strcat(server,user);

	dir=opendir(server);
	
	if(dir==NULL){
		printf("Error! Unable to open directory.\n");
		exit(1);
	}

	while( (sd=readdir(dir)) != NULL ){
		if( strstr(sd->d_name,fname)!=NULL ){
			parts[count].partname=(char *)malloc(10);
			parts[count].content=(char *)malloc(1024);
			//printf("File name is : %s\n",sd->d_name);

			//get partname after 2 dot and store
			strcpy(filename,sd->d_name);
			token=strtok(filename,".");

			while( token!=NULL ){
			parts[count].partname=token;
      			token = strtok(NULL, ".");
			}
			parts[count].partname=strdup(parts[count].partname);


			//read file and store
			strcpy(fpath,server);
			//printf(">>>%s\n",fpath);
			strcat(fpath,"/");
			strcat(fpath,sd->d_name);
			fp=fopen(fpath,"r");
			if(fp==NULL){
			printf("Fialed to read file.\n");
			exit(1);
			}				

			fseek(fp,0,SEEK_END);	
			len=ftell(fp);
			rewind(fp);
			fread(parts[count].content,len,1,fp);
			//printf("Part name is : %p\n",parts[count].partname);
			//printf("Content name is : %s\n",parts[count].content);

			count++;
			
		}
	}

	closedir(dir);
	return parts;

}


/*------------------------------------------------------------------------
 * list - get the file name into a list
 *------------------------------------------------------------------------
 */
char *list(char *user){	

	DIR *dir;
	struct dirent *sd;
	int i;
	char filename[10];
	char fnum[10];
	char *mylist=(char *)malloc(100);
	strcpy(mylist,"-");

	for(i=1;i<5;i++){
	strcpy(filename,"./DFS");
	sprintf(fnum, "%d", i);
	strcat(filename,fnum);
	strcat(filename,"/");
	strcat(filename,user);
	dir=opendir(filename);
	
	if(dir==NULL){
		printf("Error! Unable to open directory.\n");
		exit(1);
	}

	while( (sd=readdir(dir)) != NULL ){
		if(strcmp(sd->d_name,"..")!=0&&strcmp(sd->d_name,".")!=0){
			strcat(mylist,sd->d_name);
			strcat(mylist,"-");
		}

	}

	}		
	printf("LIST is:%s\n",mylist);
	closedir(dir);
	
	return mylist;
}

/*------------------------------------------------------------------------
 * put - collect pieces and store them
 *------------------------------------------------------------------------
 */
void put(char * dir,int server,char *filename,int hash,char *user){

	FILE *fp;
	char filepath[100],fname[100];
	char *read_header=NULL;
	char *read_req=NULL;
	int readlen=0;
	char *servernum;
	int num,len;
	char path[100];


	strcpy(path,"./");

	strcat(path,dir);
	strcpy(filepath,path);
	strcat(filepath,"/");
	strcat(filepath,user);
	strcat(filepath,"/");
	strcat(filepath,filename);
	
	servernum=strtok(dir,"S");
	servernum=strtok(NULL," ");
	num=atoi(servernum);

	fp=fopen(filename,"r");
	if(fp==NULL){
		printf("Failed to read file.\n");
		exit(1);
	}	

	fseek(fp,0,SEEK_END);	
	len=ftell(fp);
	rewind(fp);

	fclose(fp);
	
	if(hash==0){
		if(num==1){
		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".1");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".2");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		}
		if(num==2){
		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".2");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".3");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		}
		if(num==3){
		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".3");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".4");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		}
		if(num==4){
		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".4");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".1");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		}

	}

	if(hash==1){
		if(num==1){
		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".4");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".1");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		}
		if(num==2){
		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".1");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".2");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		}
		if(num==3){
		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".2");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".3");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		}
		if(num==4){
		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".3");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".4");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		}

	}

	if(hash==2){
		if(num==1){
		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".3");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".4");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		}
		if(num==2){
		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".4");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".1");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		}
		if(num==3){
		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".1");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".2");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		}
		if(num==4){
		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".2");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".3");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		}

	}

	if(hash==3){
		if(num==1){
		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".2");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".3");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		}
		if(num==2){
		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".3");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".4");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		}
		if(num==3){
		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".4");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".1");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		}
		if(num==4){
		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".1");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		dfs_read(server, &read_header, &readlen,&read_req);
		strcpy(fname,filepath);
		strcat(fname,".2");
		fp=fopen(fname,"w+");
		fputs(read_req,fp);

		}

	}
		fclose(fp);
}
/*------------------------------------------------------------------------
 * readdfs - reading configuration file
 *------------------------------------------------------------------------
 */

dfslist *dfs(void){

	FILE *fp;	
	char *line=NULL;
	size_t len=0;
	ssize_t read;

	char *item;
	int i;

	dfslist *ws =malloc(sizeof(char*) * 2);
	for(i=0;i<2;i++){
	ws[i].username=(char *)malloc(10);
	ws[i].password=(char *)malloc(10);
	}
	int count=0;
	
	fp=fopen("dfs.conf","r");
	if(fp==NULL){
		printf("Failed to read file.\n");
		exit(1);
	}

	while((read=getline(&line,&len,fp)) != -1){
		item=strtok(line," ");
		strcpy(ws[count].username,item);
		item=strtok(NULL," ");
		strcpy(ws[count].password,item);
		item=strtok(ws[count].password,"\n");
		strcpy(ws[count].password,item);
		count++;
	}
	fclose(fp);

	return ws;
}
/*------------------------------------------------------------------------
 * createdir - create dir for user
 *------------------------------------------------------------------------
 */
extern int errno;

void createdir(char *name,char *server){

	int e;
	struct stat sb;
	char dir[100];

	strcpy(dir,"./");
	strcat(dir,server);

	e = stat(name, &sb);
	//printf("e=%d errno=%d\n",e,errno);
	if (e == 0){
		if (sb.st_mode & S_IFDIR)
		printf("%s is a directory.\n",name);
		if (sb.st_mode & S_IFREG)
		printf("%s is a regular file.\n",name);
		// etc.
		}else{
		printf("stat failed.\n");
			if (errno = ENOENT){
			printf("The directory does not exist. Creating new directory...\n");
		// Add more flags to the mode if necessary.
			strcat(dir,"/");
			strcat(dir,name);
			e = mkdir(dir, S_IRWXU);
			if (e != 0){
			printf("mkdir failed; errno=%d\n",errno);
			}else{
			printf("created the directory %s\n",name);
			}
		}
	}
}
/*------------------------------------------------------------------------
 * createsubfolder - create subfolder
 *------------------------------------------------------------------------
 */
void createsubfolder(char *name,char *server,char *subfolder){

	int e;
	struct stat sb;
	char dir[100];

	strcpy(dir,"./");
	strcat(dir,server);

	e = stat(name, &sb);
	//printf("e=%d errno=%d\n",e,errno);
	if (e == 0){
		if (sb.st_mode & S_IFDIR)
		printf("%s is a directory.\n",name);
		if (sb.st_mode & S_IFREG)
		printf("%s is a regular file.\n",name);
		// etc.
		}else{
		printf("stat failed.\n");
			if (errno = ENOENT){
			//printf("The directory does not exist. Creating new directory...\n");
		// Add more flags to the mode if necessary.
			strcat(dir,"/");
			strcat(dir,name);
			strcat(dir,"/");
			strcat(dir,subfolder);
			e = mkdir(dir, S_IRWXU);
			if (e != 0){
			printf("mkdir failed; errno=%d\n",errno);
			}else{
			printf("created the directory %s\n",name);
			}
		}
	}
}
