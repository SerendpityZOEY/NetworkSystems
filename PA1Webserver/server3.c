#include <sys/types.h>
#include <sys/socket.h>	/*The header file socket.h includes a number of definitions of structures needed for sockets*/
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/errno.h>
#include <netinet/in.h>/*contains constants and structures needed for internet domain address*/
#include <netdb.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/poll.h>

#define	QLEN		  23	/* maximum connection queue length*/
#define	BUFSIZE		10000
#define VERSION 23
#define _GNU_SOURCE

#define NOTFOUND  404
#define BADREQUEST 400
#define NOTIMPLEMENTED 501
#define INTERNALSERVERERROR 500
#define PORT "8097"  /* the port number */
extern int	errno;
int		errexit(const char *format, ...);
int		echo(int fd);
int		errorhandling(int type, char *s1, char *s2, int socket_fd);
char*		readtype();

void sigchld_handler(int s)
{
    /* waitpid() might overwrite errno, so we save and restore it*/
    int saved_errno = errno;

    while(waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}


/* sockaddr_in containing an internet address*/
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(void)
{

    /*file descriptor*/
    int sockfd, newsockfd;
    /*address info*/ 
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    struct sigaction sa;
    int yes=1;
    char s[INET6_ADDRSTRLEN];
    char buf[BUFSIZE];
    int rv,timervalue;
    /*fd structure for timer*/
    //    struct pollfd{
    //	int fd;
    //	short events;
    //	short revents;};
    struct pollfd ufds[1];		




    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    /* loop through all the results and bind to the first we can*/
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("ERROR: opening socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                sizeof(int)) == -1) {
            perror("ERROR: setsockopt");
            exit(1);
        }
	/*binds a socket to an address*/
        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("ERROR: on binding");
            continue;
        }

        break;
    }
    /*free up the memory*/
    freeaddrinfo(servinfo);

    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }
    /*listen on the socket for connections*/
    if (listen(sockfd, QLEN) == -1) {
        perror("listen");
        exit(1);
    }
    /*reap all dead processes*/
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    printf("server: waiting for connections...\n");
    /*accept an incoming connection on a listening socket*/
    while(1) { 
        sin_size = sizeof their_addr;
        newsockfd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (newsockfd == -1) {
            perror("ERROR: on accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);
        printf("server: got connection from %s\n", s);
	/* this is the child process*/
        if (!fork()) {
            close(sockfd); // child doesn't need the listener
		while(1)
		{	/*implement poll for timer*/
			ufds[0].fd=newsockfd;ufds[0].events=POLLIN;
			timervalue=poll(ufds,1,10000);
				if (timervalue == -1) {
					/*poll failure*/
    					perror("poll");
				} else if (timervalue == 0) {
					/*10s idle and close connection*/
    					printf("Timeout occurred!  No data after 10 seconds.\n");break;
				} else {
    					/* check for events on socket: */ 
					if (ufds[0].revents & POLLIN) {				
					if (echo(newsockfd) == -1)
                			perror("send");}
					}
		}
		close(newsockfd);
            	exit(0);
        		}
        		close(newsockfd);
    		}
    		return 0;
}
/*------------------------------------------------------------------------
 * echo - response to request and reading files
 *------------------------------------------------------------------------
 */
int echo(int fd)
{
	int j, fileFd,buflen;
	long i, cc, len;
	char buffer[BUFSIZE];
	char	method[100];
	char	url[100];
	char	version[100];

	/* read request from client */
	cc =read(fd,buffer,BUFSIZE);
	/* read failure */
	if(cc <0) {
		errorhandling(INTERNALSERVERERROR,"The server experiences unexpected error.",buffer,fd);
		errexit("echo read: %s\n", strerror(errno));
	}
	/* number of bytes read */
	if(cc > 0 && cc <BUFSIZE){
		sscanf(buffer, "%s %s %s",method,url,version);
		/*400 ERROR alert*/
		if(strcmp(method,"GET")){errorhandling(BADREQUEST,"Invalid Method.",buffer,fd);}
		if(strcmp(version,"HTTP/1.1")){errorhandling(BADREQUEST,"Invalid Version.",buffer,fd);}
		if(strstr(url,",")||strstr(url,"*")){errorhandling(BADREQUEST,"Invalid URL.",buffer,fd);}
/*		for(i=0;i<BUFSIZE;i++) { 
		if((url[i] == '*')||(url[i]==',')) {
			errorhandling(BADREQUEST,"Invalid URL.",buffer,fd);
		}
	}
*/
		printf("Method is: %s\n",method);
		printf("URL is: %s\n",url);
		printf("Version is: %s\n",version);		
		printf("Echo: %s",buffer);
		/* terminate the buffer */
		buffer[cc]=0;
}	/*bytes read equals to or exceeds the BUFSIZE*/
	else errexit("echo write: %s\n", strerror(errno));


	/* null terminate after the second space to ignore extra stuff */
	for(i=4;i<BUFSIZE;i++) { 
			if(buffer[i] == ' ') { /* string is "GET URL " +lots of other stuff */
			buffer[i] = 0;
			break;
		}
	}

	/* convert no filename to index file */
	if( !strncmp(&buffer[0],"GET /\0",6) || !strncmp(&buffer[0],"get /\0",6) ) 
		{(void)memcpy(url,"/index.html",13);}


	/*read from ws.conf and construct a struct contains ext and type*/
	   FILE *stream;
           const char kw1[50]=".html text/html";
	   const char kw2[50]="DocumentRoot";
           char *token;
	   char root[100];
	   typedef struct{
		char ext[20];
		char type[20];
	}extensions;
	extensions record[100];
	char lyne[100];
	char *item;
	int reccount=0;
	int k;
	char * fstr;
           stream = fopen("ws.conf", "r");
           if (stream == NULL)
               exit(EXIT_FAILURE);

	int flag = 0;
           while (fgets(lyne,50,stream)) {

		if (strstr(lyne,kw1)) flag = 1;
		if(flag){
			//printf("%s", lyne);
			item=strtok(lyne," ");
			strcpy(record[reccount].ext,item);

			item=strtok(NULL," \n");
			strcpy(record[reccount].type,item);

			//printf("%s\n",record[reccount].type);
			reccount++;
		}
		/*reading the doc root from ws.conf*/
               if(strstr(lyne,kw2)){		 
		sscanf(lyne,"%*s \"%[^\"\n]\"",root);; 
		}
           }
		
           fclose(stream);
/*		for(k=0;k<reccount;k++){
			printf("%s\n",record[k].type);
		}
	These lines can test reading content type from ws.conf
*/
	buflen=strlen(buffer);
	fstr = (char *)0;
	for(i=0;record[i].ext != 0;i++) {
		len = strlen(record[i].ext);
		if( !strncmp(&buffer[buflen-len], record[i].ext, len)) {
			fstr =record[i].type;
			break;
		}
	}
	/*501 ERROR alert*/
	if(fstr == 0) {errorhandling(NOTIMPLEMENTED,"file extension type not supported",buffer,fd);}

	/*replace the doc root */
	//char* request_url=url;
	//char* filepath=malloc(strlen(root)+strlen(request_url)+1);
	char* filepath=malloc(strlen(root)+strlen(url)+1);
	strcpy(filepath,root);
	strcat(filepath,url);
	
	/* open the file and handle 404 ERROR*/
	if((fileFd = open(filepath,O_RDONLY))==-1){
		//errorhandling(NOTFOUND, "Failed to open file",buffer,fd);
	}	

	/* get length of file */
	else {len = (long)lseek(fileFd, 0, SEEK_END); /* lseek to the file end to find the length */
	      (void)lseek(fileFd, (off_t)0, SEEK_SET); /* lseek back to the file start ready for reading */
}
 	//printf("url is %s\n",url);
	//printf("type is %s\n",fstr);
	//printf("path is %s\n",filepath);
        (void)sprintf(buffer,"HTTP/1.1 200 OK\nContent-Length: %ld\nConnection: keep-alive\nContent-Type: %s\n\n",len, fstr); /* Header + a blank line */
	
	/*send header information*/
	(void)write(fd,buffer,strlen(buffer));
	/*sending files to file descriptor*/
	while (	(cc = read(fileFd, buffer, BUFSIZE)) > 0 ) {
		(void)write(fd,buffer,cc);
	}

	sleep(1);	/* allow socket to drain before signalling the socket is closed */
	close(fd);
	exit(1);
}

/*------------------------------------------------------------------------
 * errexit - print an error message and exit
 *------------------------------------------------------------------------
 */
int
errexit(const char *format, ...)
{
        va_list args;
	
        va_start(args, format);
        vfprintf(stderr, format, args);
        va_end(args);
        exit(1);
}


/*------------------------------------------------------------------------
 * errorhandling - print error in webpage
 *------------------------------------------------------------------------
 */
int errorhandling(int type, char *s1, char *s2, int socket_fd)
{
	int fd ;
	char logbuffer[BUFSIZE*2];

	switch (type) {
	case NOTFOUND: 
		(void)write(socket_fd, "HTTP/1.1 404 Not Found\nContent-Length: 139\nConnection: close\nContent-Type: text/html\n\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>404 Not Found</h1>\nThe requested URL was not found on this server.\n</body></html>\n",227);
		(void)sprintf(logbuffer,"NOT FOUND: %s:%s",s1, s2); 
		break;
	case BADREQUEST:
		  (void)write(socket_fd,"HTTP/1.1 400 Badrequest\nContent-Length: 185\nConnection: close\nContent-Type: text/html\n\n<html><head>\n<title>400 Badrequest</title>\n</head><body>\n<h1>Badrequest</h1>\nThe requested URL, file type or operation is not allowed on this simple static file webserver.\n</body></html>\n",271);
		  (void)sprintf(logbuffer,"BADREQUEST:%s:%s",s1,s2);break;
	case NOTIMPLEMENTED:
		  (void)write(socket_fd,"HTTP/1.1 501 NotImplemented\nContent-Length: 160\nConnection: close\nContent-Type: text/html\n\n<html><head>\n<title>501 NotImplemented</title>\n</head><body>\n<h1>501 NotImplemented</h1>\nThe requested file type or operation is not implemented.\n</body></html>\n",276);
		  (void)sprintf(logbuffer,"NOTIMPLEMENTED:%s:%s",s1,s2);break;
	case INTERNALSERVERERROR:
		  (void)write(socket_fd,"HTTP/1.1 500 InternalSeverError\nContent-Length: 140\nConnection: close\nContent-Type: text/html\n\n<html><head>\n<title>500 InternalSeverError</title>\n</head><body>\n<h1>InternalSeverError</h1>\nThe server experiences unexpected errors.\n</body></html>\n",271);
		  (void)sprintf(logbuffer,"INTERNALSERVERERROR:%s:%s",s1,s2);break;

	}
}
          
