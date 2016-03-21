/*Header for sending and parsing*/
#include <ctype.h>
#include <fcntl.h>
#include <pthread.h>
#include <netinet/in.h>
#include <netdb.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>

/*header for timer*/
#include <stdarg.h>
#include <time.h>

/*header for systemcall*/
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>

#define DEFAULT_HTTP_PORT "80"
#define DEFAULT_METHOD "GET "
#define DEFAULT_VERSION " HTTP/1.0"  
#define MAX_QUEUE 100
#define MAX_NUM_THREADS 100
#define BUF_START_SIZE 2560000
#define MAX_BUF_SIZE 65536000    /*64 kb*/
#define CRLF "\r\n"
#define DUBCRLF "\r\n\r\n"
#define SO_ORIGINAL_DST 80

#define HTTP_ERR_400 "HTTP/1.0 400 Bad Request\r\n\r\n"
#define HTTP_ERR_500 "HTTP/1.0 500 Internal Server Error\r\n\r\n"
#define HTTP_ERR_501 "HTTP/1.0 501 Not Implemented\r\n\r\n" 
#define HTTP_ERR_502 "HTTP/1.0 502 Bad Gateway\r\n\r\n"

pthread_mutex_t count_lock, cache_write_lock, timer_lock;
sem_t cache_read_sem;
int num_threads = 0;

void *kill_thread();

/*Declaration for helpers*/
enum {FALSE, TRUE};

void send_err(int socket, char *msg);
int hasdoublecrlf(void * buf);

void logEvent(const char *format, ...);
void getInterfaceIP(char* interface, char* ipAddr);
int echo (int s_server, int s_client, void *buf, size_t bufsize);
int Send(int sockfd, const void *msg, int len, int flags);
void addto_iptables (int proxy_port, char *src_ip, char *dst_ip, char *serverside_ip, int src_port, char *dst_port);
void remove_iptables (int proxy_port, char *src_ip, char *dst_ip, char *serverside_ip, int src_port, char *dst_port);
/*------------------------------------------------------------------------
 * Function for proxy

Note: This version trying prefetching
 *------------------------------------------------------------------------
 */

void *process_request(void *sock_id){

  char *host;
  char *serv_port;
  void *buf = malloc(BUF_START_SIZE+1);
  size_t bufsize = BUF_START_SIZE;
  int new_s_client =  (int) (intptr_t) sock_id;
  int s_server, proxy_port;
  int length=0, i, recieved, recieved_s, sent;
  struct addrinfo hints, *servinfo, *p;

/*declare for getpeername*/
  struct sockaddr_in sin;
  socklen_t sockLen = sizeof(struct sockaddr);
  int src_port;
  char ipstr[INET6_ADDRSTRLEN];
  static char dstbuf[INET6_ADDRSTRLEN];
  char eth0_IP[INET6_ADDRSTRLEN];

/*declare for bind*/
  char SNAT[100];
  struct sockaddr_in serv_add;
  socklen_t serv_len = sizeof( struct sockaddr);
  bzero((char *)&serv_add, sizeof(serv_add));
  serv_add.sin_family = AF_INET;
  serv_add.sin_port = htons(0); 

/*declare for log*/
  int bytes_recv=0;
  int bytes_sent=0;

  pthread_detach(pthread_self());

  bzero(buf, bufsize);

  /* update number of threads currently operating */
  pthread_mutex_lock(&count_lock);
  num_threads++;
  printf("Increasing:%d\n",num_threads);
  pthread_mutex_unlock(&count_lock);

		/* recieve from client*/
		recieved = read(new_s_client, buf, bufsize);
		if(recieved < 0){
		printf("recieved error\n");
		free(host);
		free(buf);
		kill_thread();
		pthread_cancel(pthread_self());
		return NULL;
		}else if(recieved == 0){
		close(new_s_client);
		close(s_server);
		return NULL;
		}
		printf("recv from client:%s\n",buf);

	/*getpeername -- client IP*/
	getpeername(new_s_client, (struct sockaddr*)&sin, &sockLen);
    struct sockaddr_in *s = (struct sockaddr_in *)&sin;
    src_port = ntohs(s->sin_port);
    inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);


	/*Get the server ip*/
	struct sockaddr_in dstaddr;
	socklen_t len = sizeof(dstaddr);

	if (getsockopt(new_s_client, SOL_IP, SO_ORIGINAL_DST, (struct sockaddr *) &dstaddr, &len) == -1) {
		perror("getsockopt");
		close(new_s_client);
	}

	inet_ntop(dstaddr.sin_family, &dstaddr.sin_addr, dstbuf, sizeof(dstbuf));
	printf("original destination %s:%u\n", dstbuf, ntohs(dstaddr.sin_port));

	host = malloc(strlen(dstbuf));
	sprintf(host, "%s", dstbuf);

	serv_port = malloc(sizeof (ntohs(dstaddr.sin_port)));
	sprintf(serv_port, "%u", ntohs(dstaddr.sin_port));

	getInterfaceIP("eth0", eth0_IP);
/*
	printf("client address: %s\n", ipstr);
//	printf("proxy port of server side: %d\n", proxy_port);
	printf("port of client: %d\n", src_port);
	printf("serverside_ip: %s\n", eth0_IP);
	printf("dst port:%s\n",serv_port);
	//addto_iptables (proxy_port, ipstr, dstbuf, eth0_IP, src_port, serv_port);
*/
	/* send request to the specified host */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

	if ( (getaddrinfo(host, serv_port, &hints, &servinfo)) != 0) 
	{
		send_err(new_s_client, HTTP_ERR_502);
		free(host);
		free(buf);
		kill_thread();
		pthread_cancel(pthread_self());
		return NULL;
	}

	for(p = servinfo; p != NULL; p = p->ai_next) 
	{
		if ((s_server = socket(p->ai_family, p->ai_socktype,
						p->ai_protocol)) < 0){
			kill_thread();
			pthread_cancel(pthread_self()); 
			return NULL;
		}

		if ( (bind(s_server, (struct sockaddr *)&serv_add, sizeof(serv_add))) < 0){
			perror("cannot bind to socket");
			exit(1);
		}

		/*getsockname -- source port*/
		getsockname(s_server, (struct sockaddr*)&serv_add, &serv_len);
		proxy_port = ntohs(serv_add.sin_port);

		sprintf(SNAT, "iptables -t nat -A POSTROUTING --protocol tcp -d %s -j SNAT --sport %d --to-source %s", dstbuf, proxy_port, ipstr);
		system(SNAT);

		if (connect(s_server, p->ai_addr, p->ai_addrlen) < 0) 
		{
			close(s_server);
			continue;
		}
		break;
	}
    freeaddrinfo(servinfo);


	if (p == NULL){
		send_err(new_s_client, HTTP_ERR_500);
		free(host);
		free(buf);
		kill_thread();
		pthread_cancel(pthread_self());
		return NULL;
	}

		/*Send req to server*/
		if( ( sent = write(s_server, buf, recieved)) == -1 ){
			printf("Send error\n");
			free(host);
			free(buf);
			kill_thread();
			pthread_cancel(pthread_self());
			return NULL;
		}
		//printf("sent:%d\n", sent);
		bytes_sent += recieved;
		bzero(buf, bufsize);

	pthread_mutex_lock(&cache_write_lock);
	for (i = 0; i < MAX_NUM_THREADS; i++)
		sem_wait(&cache_read_sem);

//echo
	bytes_recv = echo(s_server, new_s_client, buf, bufsize);
	//printf("bytes recieved:%d\n",bytes_recv);

	for (i = 0; i < MAX_NUM_THREADS; i++)
		sem_post(&cache_read_sem);
	pthread_mutex_unlock(&cache_write_lock);

/*logging*/
	logEvent("%s %d %s %s %d %d\n", ipstr, src_port, host, serv_port, bytes_sent, bytes_recv );

	sprintf(SNAT, "iptables -t nat -D POSTROUTING --protocol tcp -d %s -j SNAT --sport %d --to-source %s", dstbuf, proxy_port, ipstr);
	system(SNAT);

	pthread_mutex_lock(&count_lock);
	num_threads--;
	printf("Decreasing:%d\n",num_threads);
	pthread_mutex_unlock(&count_lock);

	free(host);
	pthread_cancel(pthread_self());
	return NULL;
}

void *kill_thread(){
	pthread_mutex_lock(&count_lock);
	num_threads--;
	printf("Decreasing:%d\n",num_threads);
	pthread_mutex_unlock(&count_lock);
}

int main(int argc, char * argv[]){

	int MULTITHREADED = TRUE;
	void (*ret)(int);
	int s_client;
	int new_s_client;
	struct sockaddr_in sin;
	socklen_t sockLen = sizeof(struct sockaddr);
	uint16_t portnum;

	/*DNAT system call*/
	char DNAT[100];
	char eth1_IP[INET6_ADDRSTRLEN];
	char ip[INET6_ADDRSTRLEN];

	pthread_t thread;	  
	pthread_attr_t thread_attr;

	pthread_attr_init(&thread_attr);
	pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);

	if(geteuid() != 0){
		printf("This program must be run as root\n");
		exit(1);
	}
 
	ret = signal(SIGPIPE, SIG_IGN);
	if (ret == SIG_ERR){
		perror(argv[0]);
		exit(1);
	}

	if (argc == 2)	  
		portnum = (uint16_t)atoi(argv[1]);
	else{
		fprintf(stderr, "usage: proxy [-t] <portnum>\n");
		exit(1);
	}
  
	bzero((char *)&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(portnum); 

	/*  open a socket and attempt to bind to the given port */
	if ( (s_client = socket(PF_INET, SOCK_STREAM, 0)) < 0){
		perror("error requesting socket");
		exit (1);
	}

	setsockopt(s_client, SOL_SOCKET, SO_REUSEADDR, NULL, 0);

	if ( (bind(s_client, (struct sockaddr *)&sin, sizeof(sin))) < 0){
		perror("cannot bind to socket");
		exit(1);
	}

/*DNAT - System call*/
	getInterfaceIP("eth1", eth1_IP);
	//printf("proxy ip:%s\nproxy port num:%d\n", eth1_IP, sin.sin_port);
	sprintf(DNAT, "iptables -t nat -A PREROUTING --protocol tcp -i eth1 -j DNAT --to %s:%d", eth1_IP, portnum);
	system(DNAT);

	listen(s_client, MAX_QUEUE);
  
	pthread_mutex_init(&count_lock, NULL);
	pthread_mutex_init(&cache_write_lock, NULL);
	sem_init(&cache_read_sem, PTHREAD_PROCESS_PRIVATE, MAX_NUM_THREADS);

	while (1){
	 if (num_threads < MAX_NUM_THREADS){

		 if ( (new_s_client = accept(s_client, (struct sockaddr *)&sin, &sockLen)) < 0)
			continue;
			inet_ntop(sin.sin_family, &sin.sin_addr, ip, sizeof(ip));
			printf("connection from %s:%u\n", ip, ntohs(sin.sin_port));

		/*Implement multi-thread*/
		 if (MULTITHREADED)
		 {
		     if (pthread_create(&thread, &thread_attr, process_request, (void *) (long) new_s_client) != 0)
		     {
			     send_err(new_s_client, HTTP_ERR_500);
			     close(new_s_client);
		     }
		 }else{
			 process_request((void *) (long) new_s_client);
		  }
	 }else{
		sleep(1);
	 }
  }
  return 1;
}


/* a function to call send() in a loop with error checking. returns
   the total number of bytes sent or -1 on error */
int Send(int sockfd, const void *msg, int len, int flags)
{
	 int total = 0;        // how many bytes we've sent
	     int bytesleft = len; // how many we have left to send
		     int n;

			     while(total < len) {
					         n = send(sockfd,(char *) msg+total, bytesleft, 0);
							         if (n == -1) { break; }
									         total += n;
											         bytesleft -= n;
													     }

				     len = total; // return number actually sent here

					     return n==-1?-1:0; // return -1 on failure, 0 on success
}

/* Check if buf is terminated by a \r\n\r\n, return 1 if TRUE, 0 otherwise */
int hasdoublecrlf(void * buf)
{
	if (strstr((char *)buf, DUBCRLF))
		return 1;
	if (strstr((char *)buf, "\n\n"))
		return 1;
	return 0;
}

/* send msg over socket, then close socket */
void send_err(int socket, char *msg)
{
	Send(socket, msg, strlen(msg), 0);
	close(socket);
}


void logEvent(const char *format, ...)
{
	static FILE* logFile;
	static struct tm * timeinfo;
	static char* timedFormat;
	static time_t rawtime;
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	va_list args;
	va_start(args, format);

	if ((logFile = fopen ("./proxy.log", "a")) == NULL){
		printf("File open failed\n");
	}
	
	fprintf(logFile,"[%d %d %d %d:%d:%d] \n", timeinfo->tm_mday, timeinfo->tm_mon + 1,
				timeinfo->tm_year + 1900, timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
	vfprintf(logFile, format, args);
	fflush (logFile);
	va_end(args);
}

// ipAddr must be declared as char[16]
void getInterfaceIP(char* interface, char* ipAddr)
{
	int fd;
	struct ifreq ifr;
	
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	
	ifr.ifr_addr.sa_family = AF_INET; // IPv4
	
	strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
	
	ioctl(fd, SIOCGIFADDR, &ifr);
	
 	close(fd);

 /* display result */
	strcpy(ipAddr, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
 	printf("'%s'\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
}

int echo (int s_server, int s_client, void *buf, size_t bufsize){
	
	int recieved_s,sent;
	int bytes_recv = 0;

		if( (recieved_s = read(s_server, buf, bufsize))!=0 ){
		/*recieved from server*/

		bytes_recv += recieved_s;	
		printf("recv from server:%s\n",buf);
		Send(s_client, buf, recieved_s, 0);
/*
		if ( (sent = write(s_client, buf, recieved_s)) == -1){
		printf("Send error\n");
		return 1;
		}
		printf("sent:%d\n", sent);
*/
		//bzero(buf, bufsize);
		}

		free(buf);		
		close(s_server);
		close(s_client);
		return bytes_recv;

}

void addto_iptables (int proxy_port, char *src_ip, char *dst_ip, char *serverside_ip, int src_port, char *dst_port){

	char SNAT[100];
	char DNAT2[100];
	char SNAT2[100];
	//sprintf(SNAT, "iptables -t nat -A POSTROUTING --protocol tcp -j SNAT --sport %d --to-source %s", proxy_port, src_ip);
	sprintf(SNAT, "iptables -t nat -A POSTROUTING --protocol tcp -d %s -j SNAT --sport %d --to-source %s", dst_ip, proxy_port, src_ip);
	system(SNAT);

	sprintf(DNAT2, "iptables -t nat -A PREROUTING -p tcp -i eth0 -s %s --dport %d -j DNAT --to %s:%d", dst_ip, proxy_port, serverside_ip, proxy_port);
	system(DNAT2);

	sprintf(SNAT2, "iptables -t nat -A POSTROUTING -p tcp -d %s --dport %d -j SNAT --to %s:%s", src_ip, src_port, dst_ip, dst_port);
	system(SNAT2);

}

void remove_iptables (int proxy_port, char *src_ip, char *dst_ip, char *serverside_ip, int src_port, char *dst_port){
	char SNAT[100];
	char DNAT2[100];
	char SNAT2[100];
	sprintf(SNAT, "iptables -t nat -D POSTROUTING --protocol tcp -j SNAT --sport %d --to-source %s", proxy_port, src_ip);
	system(SNAT);

	sprintf(DNAT2, "iptables -t nat -D PREROUTING -p tcp -i eth0 -s %s --dport %d -j DNAT --to %s:%d", dst_ip, proxy_port, serverside_ip, proxy_port);
	system(DNAT2);

	sprintf(SNAT2, "iptables -t nat -D POSTROUTING -p tcp -d %s --dport %d -j SNAT --to %s:%s", src_ip, src_port, dst_ip, dst_port);
	system(SNAT2);
}
