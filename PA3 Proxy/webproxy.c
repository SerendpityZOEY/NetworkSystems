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

/*Header for cache*/
#include <sys/stat.h>
#include <regex.h>
/*Header for timer*/
#include <time.h>
#define TIME_PERIOD 60

/*Header for linked list*/
#include<stdbool.h>

/*Header for md5*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__APPLE__)
#  define COMMON_DIGEST_FOR_OPENSSL
#  include <CommonCrypto/CommonDigest.h>
#  define SHA1 CC_SHA1
#else
#  include <openssl/md5.h>
#endif

#define DEFAULT_HTTP_PORT "80"
#define DEFAULT_METHOD "GET "
#define DEFAULT_VERSION " HTTP/1.0"  
#define MAX_QUEUE 100
#define MAX_NUM_THREADS 100
#define BUF_START_SIZE 256
#define MAX_BUF_SIZE 65536    /*64 kb*/
#define CRLF "\r\n"
#define DUBCRLF "\r\n\r\n"

#define HTTP_ERR_400 "HTTP/1.0 400 Bad Request\r\n\r\n"
#define HTTP_ERR_500 "HTTP/1.0 500 Internal Server Error\r\n\r\n"
#define HTTP_ERR_501 "HTTP/1.0 501 Not Implemented\r\n\r\n" 
#define HTTP_ERR_502 "HTTP/1.0 502 Bad Gateway\r\n\r\n"

/*For cache*/
#define CACHE_DIRECTORY "./proxy_cache"
#define SHA_DIGEST_LENGTH 32

pthread_mutex_t count_lock, cache_write_lock, timer_lock;
sem_t cache_read_sem;
int num_threads = 0;

void *kill_thread();

/*For cache*/
struct cacheTree
{
	char hash[SHA_DIGEST_LENGTH+1];
	long cacheTime;
	struct cacheTree *next;
};
//typedef struct cacheTree *cacheindex_T;
//cacheindex_T cache_index;

struct cacheTree *head = NULL;

/*Declaration for helpers*/
enum {FALSE, TRUE};
/* a function to call send() in a loop with error checking. returns
   the total number of bytes sent or -1 on error */
int Send(int sockfd, const void *msg, int len, int flags);

/* Places the first 3 characters of the method into memory designated by method 
   Determines if request is a GET request, returns 1 if TRUE, 0 otherwise */ 
int parse_method(void *buf, char *method);

/* Parse the URL from header, allocate memory and store url,
   return a pointer to url or NULL if allocation fails or there
   is no url field in the header (invalid header) */
char *parse_url(void *buf, size_t bufsize);

/* Places the first 8 characters of the version into memory designated by http_version.
   Determines if this string is a valid HTTP version, returning 1 if TRUE, 0 otherwise */
int parse_http_version(void *buf, size_t bufsize, char *http_version);

/* Parses host and path apart, putting the path into url, and returning a pointer 
   to host, or NULL if there is no host, or if memory allocation fails */ 
char *parse_host(char *url, void *buf, size_t bufsize);	

/* Return the port number if included in host header, 0 otherwise */
char *parse_port(char *host);

/* Perform cleanup on http request from client and send it
   out over s_server. Return 1 on successful send, 0 otherwise */ 
int send_http_request(int s_server, char *host, char *url, void *buf, size_t *bufsize, int length);

/* Check if buf is terminated by a \r\n\r\n, return 1 if TRUE, 0 otherwise */
int hasdoublecrlf(void * buf);

/* send msg over socket, then close socket */
void send_err(int socket, char *msg);

/*Declaration for cache*/
//static void cacheTree_free(struct cacheTree **head);

/* return 1 if url composed of host ^ path is in cache index, 0 otherwise */ 
int proxycache_iscached(char *host, char *path);

/* send the cached page over sock */
void proxycache_returncached(char *host, char *path, int sock, void *buf, size_t bufsize);

/* write the page at url host + path to a cache file, and add it to the cache index */
int proxycache_addtocache(char *host, char *path, int s_server,int s_client, void *buf, size_t *bufsize);
int linkcache_addtocache(char *host, char *path, int s_server,int s_client, void *buf, size_t *bufsize);
void print_list();

/*Timer*/
unsigned int get_current_time(void);
int timeout = 60;
int TIMEWAIT;	

/*Link Prefetching*/
void *prefetching(void *sock_id, char *host, char *url, char *serv_port);
int read_file(char *host, char *path, void *sock_id, char *serv_port);
/*------------------------------------------------------------------------
 * Function for proxy

Note: This version trying prefetching
 *------------------------------------------------------------------------
 */

void *process_request(void *sock_id)
{
  char method[4];    /* strlen("GET")+1 */
  char *url;
  char http_version[9];		/* strlen("HTTP/X.X")+1 */
  char *host;
  char *serv_port;
  void *buf = malloc(BUF_START_SIZE+1);
  size_t bufsize = BUF_START_SIZE;
  int new_s_client =  (int) (intptr_t) sock_id;
  int s_server;
  int GOT_CACHED;
  int length=0, i, recieved, available=BUF_START_SIZE;
  struct addrinfo hints, *servinfo, *p;

  //pthread_detach(pthread_self());

  bzero(buf, bufsize);

  /* update number of threads currently operating */
  pthread_mutex_lock(&count_lock);
  num_threads++;
  printf("Increasing:%d\n",num_threads);
  pthread_mutex_unlock(&count_lock);

  /* recieve request from client */
    length = 0;
	available = bufsize;
    while ( (recieved = recv(new_s_client, ((char *)buf+length), available, 0)))
	{
		available -= recieved;
		length += recieved;

		if (hasdoublecrlf(buf))
			break;

		if (available == 0)
		{
			if (bufsize < MAX_BUF_SIZE)
				bufsize *= 2;
			if ( (buf = realloc(buf, bufsize+1)) == NULL)
				break;
			available = bufsize/2;
		}
	}

	/* parse request */
	bzero(method, sizeof(method));
	bzero(http_version, sizeof(http_version));
	if (!parse_method(buf, method))
	{
		send_err(new_s_client, HTTP_ERR_501);
		kill_thread();
		//pthread_cancel(pthread_self());
		return NULL;
	}

	if ( (url = parse_url(buf, bufsize)) == NULL)
	{
		send_err(new_s_client, HTTP_ERR_400);
		kill_thread();
		//pthread_cancel(pthread_self());
		return NULL;
	}

	if (!parse_http_version(buf, bufsize, http_version))
	{
		send_err(new_s_client, HTTP_ERR_400);
		kill_thread();
		free(url);
		//pthread_cancel(pthread_self());
		return NULL;
	}

	if ( (host = parse_host(url, buf, bufsize)) == NULL)
	{
		send_err(new_s_client, HTTP_ERR_400);
		kill_thread();
		free(url);
		//pthread_cancel(pthread_self());
		return NULL;
	}

	if ( (serv_port = parse_port(host)) == NULL)
		serv_port = DEFAULT_HTTP_PORT;

	/*check if cached or not*/
	if(proxycache_iscached(host,url) ){

		printf(">>>Cache hit!\nPage returned from cached file\n");
		pthread_mutex_lock(&cache_write_lock);
		sem_wait(&cache_read_sem);
		pthread_mutex_unlock(&cache_write_lock);
		proxycache_returncached(host, url, new_s_client, buf, bufsize);
		sem_post(&cache_read_sem);
		close(new_s_client);
		free(url);
		free(host);
		free(buf);

		pthread_mutex_lock(&count_lock);
		num_threads--;
		pthread_mutex_unlock(&count_lock);
		//pthread_cancel(pthread_self());
		return NULL;

	}

	/* if not cached, send request to the specified host */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

	if ( (getaddrinfo(host, serv_port, &hints, &servinfo)) != 0) 
	{
		send_err(new_s_client, HTTP_ERR_502);
		free(url);
		free(host);
		free(buf);
		kill_thread();
		//pthread_cancel(pthread_self());
		return NULL;
	}

	for(p = servinfo; p != NULL; p = p->ai_next) 
	{
		if ((s_server = socket(p->ai_family, p->ai_socktype,
						p->ai_protocol)) < 0){
			kill_thread();
			//pthread_cancel(pthread_self()); 
			return NULL;
		}
		if (connect(s_server, p->ai_addr, p->ai_addrlen) < 0) 
		{
			close(s_server);
			continue;
		}
		break;
	}
    freeaddrinfo(servinfo);

	if (p == NULL)
	{
		send_err(new_s_client, HTTP_ERR_500);
		free(url);
		free(host);
		free(buf);
		kill_thread();
		//pthread_cancel(pthread_self());
		return NULL;
	}

	send_http_request(s_server, host, url, buf, &bufsize, length);	
	
	/* recieve response, and, write webpage to cache. Send it to the client */
	pthread_mutex_lock(&cache_write_lock);
	for (i = 0; i < MAX_NUM_THREADS; i++)
		sem_wait(&cache_read_sem);

	if (proxycache_addtocache(host, url, s_server, new_s_client, buf, &bufsize) == 0)
		GOT_CACHED = TRUE;
	else
		GOT_CACHED = FALSE;

	for (i = 0; i < MAX_NUM_THREADS; i++)
		sem_post(&cache_read_sem);
	pthread_mutex_unlock(&cache_write_lock);

/*Link Prefetching here*/
	//read_file(host, url, ( void *) (long) s_server, serv_port);

	pthread_mutex_lock(&count_lock);
	num_threads--;
	printf("Decreasing:%d\n",num_threads);
	pthread_mutex_unlock(&count_lock);

	//pthread_exit(NULL);


	free(url);
	free(host);
	//pthread_cancel(pthread_self());
	return NULL;
}

void *kill_thread(){
	pthread_mutex_lock(&count_lock);
	num_threads--;
	printf("Decreasing:%d\n",num_threads);
	pthread_mutex_unlock(&count_lock);
}

int main(int argc, char * argv[])
{
  void (*ret)(int);
  struct sockaddr_in sin;
  int s_client;
  int new_s_client;
  socklen_t sockLen = sizeof(struct sockaddr);
  uint16_t portnum;
  int e;
  pthread_t thread;	  
  pthread_attr_t thread_attr;

  pthread_attr_init(&thread_attr);
  pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);

	e = mkdir(CACHE_DIRECTORY, S_IRWXU);
  //cache_index = proxycache_create();
 
  ret = signal(SIGPIPE, SIG_IGN);
  if (ret == SIG_ERR)
  {
	  perror(argv[0]);
	  exit(1);
  }
  
  int MULTITHREADED = TRUE;
//	TIMEWAIT=FALSE;
  if (argc == 2)	  
  	  portnum = (uint16_t)atoi(argv[1]);
  else if (argc == 3)
  {
	  timeout = atoi(argv[1]);
	  portnum = (uint16_t)atoi(argv[2]);
//	TIMEWAIT=TRUE;
  }
  else
  {
	  fprintf(stderr, "usage: proxy [-t] <portnum>\n");
      exit(1);
  }
  
  bzero((char *)&sin, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(portnum); 

  /*  open a socket and attempt to bind to the given port */
  if ( (s_client = socket(PF_INET, SOCK_STREAM, 0)) < 0)
  {
      perror("error requesting socket");
      exit (1);
  }
  setsockopt(s_client, SOL_SOCKET, SO_REUSEADDR, NULL, 0);

  if ( (bind(s_client, (struct sockaddr *)&sin, sizeof(sin))) < 0)
    {
    perror("cannot bind to socket");
      exit(1);
    }

  listen(s_client, MAX_QUEUE);
  
  pthread_mutex_init(&count_lock, NULL);
  pthread_mutex_init(&cache_write_lock, NULL);
  sem_init(&cache_read_sem, PTHREAD_PROCESS_PRIVATE, MAX_NUM_THREADS);

  while (1)
  {
	 if (num_threads < MAX_NUM_THREADS)
	 {
		 if ( (new_s_client = accept(s_client, (struct sockaddr *)&sin, &sockLen)) < 0)
			continue;
		printf("server: got connection from 127.0.0.1\n");
		//printf("current threads running: %d\n",num_threads);
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
/*------------------------------------------------------------------------
 * Function for helpers
 *------------------------------------------------------------------------
 */


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



/* Places the first 3 characters of the method into memory designated by method 
   Determines if request is a GET request, returns 1 if TRUE, 0 otherwise */ 
int parse_method(void *buf, char *method)
{
	int i;
	char *bufptr = (char *) buf;
	for (i = 0; i < 3; i++)
		method[i] = bufptr[i];
	
	method[3] = '\0';
	if (strcmp(method, "GET"))
		return 0;
	return 1;
}

/* Parse the URL from header, allocate memory and store url,
   return a pointer to url or NULL if allocation fails or there
   is no url field in the header (invalid header) */
   
char *parse_url(void *buf, size_t bufsize)
{
	size_t i, url_length=0;
	char *url;
	char *bufptr = (char *)buf;
	/* skip method, then skip any intervening whitespace */
	for (i = 0; !isspace(bufptr[i]) && i < bufsize; i++)
		;
	for ( ; isspace(bufptr[i]) && i < bufsize; i++)
		;
	for ( ; !isspace(bufptr[i]) && i < bufsize; i++)
		url_length++;
	if (url_length == 0)
		return NULL;
	i -= url_length;
	url = (char *)malloc(sizeof(char)*(url_length+1));
	if (url == NULL)
		return NULL;
	url_length = 0;
	
	for ( ; !isspace(bufptr[i]) && i <bufsize; i++) 
	{
		url[url_length++] = bufptr[i];
	}

	url[url_length] = '\0';
	return url;
}

/* Places the first 8 characters of the version into memory designated by http_version.
   Determines if this string is a valid HTTP version, returning 1 if TRUE, 0 otherwise */
int parse_http_version(void *buf, size_t bufsize, char *http_version)
{
	size_t i, j;
	char *bufptr = (char *)buf;
	/* skip method and url, then skip any intervening whitespace */
	for (i = 0; !isspace(bufptr[i]) && i < bufsize; i++)
		;
	for ( ; isspace(bufptr[i]) && i < bufsize; i++)
		;
	for ( ; !isspace(bufptr[i]) && i < bufsize; i++)
		;
	for ( ; isspace(bufptr[i]) && i < bufsize; i++)
		;
	for (j = 0; j < 8 && i < bufsize; j++)
		http_version[j] = bufptr[i++];
	http_version[j + 1] = '\0';
	if( strcmp(http_version, "HTTP/1.0") 
			&& strcmp(http_version, "HTTP/1.1"))
			return 0;
	return 1;
}

/* Parses host and path apart, putting the path into url, and returning a pointer 
   to host, or NULL if there is no host, or if memory allocation fails */ 
char *parse_host(char *url, void *buf, size_t bufsize)	
{
	int hashttp = FALSE;
	size_t i, j, host_length=0;
	char * host_hdr;
	char * header_ptr;
	char *bufptr = (char *)buf;
	/* if url is a full url, parse out host, place path at beginning
	   of array pointed to by url, and return host_hdr */
	if (strlen(url) >= strlen("HTTP://"))
		if (strcasestr(url, "HTTP://"))
		{
			url += strlen("HTTP://");
			hashttp = TRUE;
		}
	if (*url != '/')
	{
		for (i = 0 ; url[i] != '/' && i < strlen(url); i++)
			host_length++;

		host_hdr = (char *)malloc(sizeof(char)*(host_length+1));
	
		if (host_hdr == NULL)
			return NULL;
		host_length = 0;

		for (i = 0; url[i] != '/' && i < strlen(url); i++)
			host_hdr[host_length++] = url[i];
		host_hdr[host_length] = '\0';

		if (hashttp)
		{
			url -= strlen("HTTP://");
			i += strlen("HTTP://");
		}
		for (j = 0 ; i < strlen(url); i++)
			url[j++] = url[i];
		url[j] = '\0';
		if (strlen(url) == 0)
		{
			url[0] = '/';
			url[1] = '\0';
		}
		return host_hdr;
	}

	else if ( (header_ptr = (char *) (long) strcasestr(bufptr, "HOST")) == NULL)
		return NULL;

	bufsize -= (header_ptr - bufptr);
	for (i = 0; header_ptr[i] != ':' && i < bufsize; i++)
		;
	i++;
	for ( ; isspace(header_ptr[i]) && i < bufsize; i++)
		;
	for ( ; !isspace(header_ptr[i]) && i < bufsize; i++)
		host_length++;

	i -= host_length;
	host_hdr = (char *)malloc(sizeof(char)*(host_length+1));
	if (host_hdr == NULL)
		return NULL;
	host_length = 0;

	for ( ; !isspace(header_ptr[i]) && i < bufsize; i++)
		host_hdr[host_length++] = header_ptr[i];
	host_hdr[host_length] = '\0';

	

	return host_hdr;
}

/* Return the port number if included in host header, 0 otherwise */
char *parse_port(char *host)
{
	char *port_ptr;

	if ( (port_ptr = strstr(host, ":") ) == NULL)
		return NULL;
	else
		return port_ptr;
}

/* Perform cleanup on http request from client and send it
   out over s_server. Return 0 on successful send, 1 otherwise */ 
int send_http_request(int s_server, char *host, char *url, void *buf, size_t *bufsize, int length)
{
	int i, j, write_offset;
	void *sendbuf = malloc(sizeof(char)*(*bufsize));
	char *sendbufptr = (char *)sendbuf;
	char *bufptr = (char *) buf;
	bufptr[0] = '\0';

	bzero(sendbuf, *bufsize);
	/* construct first line of header and host header*/
	strncat(sendbufptr, DEFAULT_METHOD, strlen(DEFAULT_METHOD));
	strncat(sendbufptr, url, strlen(url));
	strncat(sendbufptr, DEFAULT_VERSION, strlen(DEFAULT_VERSION));
	strncat(sendbufptr, CRLF, strlen(CRLF));
	strncat(sendbufptr, "Host: ", strlen("Host: "));
	strncat(sendbufptr, host, strlen(host));
	strncat(sendbufptr, CRLF, strlen(CRLF));
				
	j = strlen(sendbufptr);
	for (i = 0; bufptr[i] != '\n'; i++)
		;
	i++;
	while (i < length)
	{
		while (i < length && j < *bufsize)
		{
			write_offset = 0;
			for ( ; bufptr[i] != '\r' && bufptr[i] != '\n' && i < length; i++)
			{
				sendbufptr[j++] = bufptr[i];
				write_offset++;
			}
			j -= write_offset;
			if (strlen((sendbufptr+j)) >= strlen("Host"))
			{
				if (strcasestr((const char *)sendbufptr + j, "Host"))
				{
					sendbufptr[j] = '\0';
					continue;
				}
			}
			if (strlen((sendbufptr+j)))
			{
				if (!strlen((sendbufptr+j)) || !strstr((const char *)sendbufptr + j, ":"))
				{
					sendbufptr[j] = '\0';
					continue;
				}
			}
				j += write_offset;

			if (bufptr[i] == '\r')
			{
				if (bufptr[i+1] == '\n')
					i += 2;
			}
			else if (bufptr[i] == '\n')
				i++;
			if (bufptr[i] == '\r' || bufptr[i] == '\n')
			{
				strncat(sendbufptr, DUBCRLF, strlen(DUBCRLF));
				if (bufptr[i] == '\r')
					i += 2;
				if (bufptr[i] == '\n')
					i++;
				break;
			}
			else
				strncat(sendbufptr, CRLF, strlen(CRLF));
		}
		if (j == *bufsize)
		{
				if (*bufsize < MAX_BUF_SIZE)
					*bufsize *= 2;
				else
					return 0;
				if ( (sendbuf = realloc(sendbuf, *bufsize+1)) == NULL)
					return 0;
				else 
					sendbufptr = (char *)sendbuf;
		}
	}
	if (!Send(s_server, sendbufptr, strlen(sendbufptr), 0))
	{
		free(sendbuf);
		return 0;
	}
	free(sendbuf);
	return 1;
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
/*
========================================================
HASH MD5
========================================================
*/
char* md5(char* inputString)
{
	int n;
	MD5_CTX c;
	ssize_t bytes = strlen(inputString);
    char *output = (char*)malloc(33);

	unsigned char out[MD5_DIGEST_LENGTH];
	MD5_Init(&c);

	MD5_Update(&c, inputString, bytes);

	MD5_Final(out, &c);

    for (n = 0; n < 16; ++n) {
        snprintf(&(output[n*2]), 16*2, "%02x", (unsigned int)out[n]);
    }

	return output;
}


/*
========================================================
CACHING
========================================================
*/

static int cacheTree_contains(char *url)
{
	int diff;
	char URLhash[SHA_DIGEST_LENGTH];
	strcpy(URLhash,md5(url));
	struct cacheTree *index = head;


/*Declaration for timer*/
    time_t t1, t2;
	t2 = time(NULL);

	while (index != NULL)
	{
		diff = strncmp(URLhash, index->hash, SHA_DIGEST_LENGTH);
		//printf("URLHash: %s, index->hash: %s",URLhash, index->hash);
		if (diff == 0){
			//printf("found %s\n", URLhash);
        	if ( (t2-index->cacheTime) < timeout ) {
				print_list();
				return 1;
        	}
		}
		else
			index = index->next;

	}          

	return 0;
}

/* return 1 if url composed of host ^ path is in cache index, 0 otherwise */ 
int proxycache_iscached(char *host, char *path)
{
	int contains;
	char *url = (char *)malloc(strlen(host) + strlen(path) + 1);
	url[0] = '\0';
	strcat(url, host);
	strcat(url, path);
	contains = cacheTree_contains(url);
	free(url);
	//printf("Contains is %d\n",contains);
	return contains;
}

static int cacheTree_add(char *url)
{
	int diff;
	char URLhash[SHA_DIGEST_LENGTH];
	strcpy(URLhash,md5(url));

/*Declaration for timer*/
    time_t t1;

	struct cacheTree* newCache = (struct cacheTree *)malloc(sizeof(struct cacheTree));
	strncpy(newCache->hash, URLhash, SHA_DIGEST_LENGTH+1);
	t1 = time(NULL);
	newCache->cacheTime = t1;

	newCache->next = head;
	head = newCache;

	return 1;

}



/* send the cached page over sock */
void proxycache_returncached(char *host, char *path, int sock, void *buf, size_t bufsize)
{
	int recieved;
	FILE *cached_file;
	char *filepath = (char *)malloc(strlen(CACHE_DIRECTORY) + SHA_DIGEST_LENGTH + 2);
	char *url = (char *)malloc(strlen(host) + strlen(path) + 1);
	
	/* construct url */
	url[0] = '\0';
	strcat(url, host);
	strcat(url, path);
	char URLhash[SHA_DIGEST_LENGTH]; 
	strcpy(URLhash,md5(url));

	/* construct file path */
	filepath[0] = '\0';
	strcat(filepath, CACHE_DIRECTORY);
	strcat(filepath, "/");
	strncat(filepath, URLhash, SHA_DIGEST_LENGTH);

	/* open cache file and send it over socket sock */
	cached_file = fopen(filepath, "r");
	while ( (recieved = fread(buf, 1, bufsize, cached_file)) > 0){
		Send(sock, buf, recieved, 0);
	}
	fclose(cached_file);
	free(url);
	free(filepath);
}


int proxycache_addtocache(char *host, char *path, int s_server,int s_client, void *buf, size_t *bufsize)
{
	int length=0, available = *bufsize; 
	int recieved;
	FILE *cache_file;
	char *filepath = (char *)malloc(strlen(CACHE_DIRECTORY) + SHA_DIGEST_LENGTH + 2);
	char *url = (char *)malloc(strlen(host) + strlen(path) + 1);
	
	/* construct url */
	url[0] = '\0';
	strcat(url, host);
	strcat(url, path);
	char URLhash[SHA_DIGEST_LENGTH]; 
	strcpy(URLhash,md5(url));

	/* construct file path */
	filepath[0] = '\0';
	strcat(filepath, CACHE_DIRECTORY);
	strcat(filepath, "/");
	strncat(filepath, URLhash, SHA_DIGEST_LENGTH);
	//printf("Writing to cache: %s\n",URLhash);
	/* recieve all headers (some message body may be recieved, but is irrelevant.
	   search for a properly formed non-cache or private header, and if found, 
	   proceed with recving and sending to client, then return 1  */
	while ( (recieved = recv(s_server,((char *)buf+length), available, 0)))
	{
		available -= recieved;
		length += recieved;

		if (hasdoublecrlf(buf))
			break;

		if (available == 0)
		{
			if (*bufsize < MAX_BUF_SIZE)
				*bufsize = *bufsize*2;
			if ( (buf = realloc(buf, *bufsize+1)) == NULL)
			{
				free(url);
				free(filepath);
				return -1;
			}
			available = *bufsize/2;
		}	
	}

	cache_file = fopen(filepath, "w");
	if (cache_file == NULL)
		return -1;

	printf("Filepath is:%s\n",filepath);

		Send(s_client, buf, length, 0);
		fwrite(buf, 1, length, cache_file);
		while ( (recieved = recv(s_server, buf, *bufsize, 0)) != 0){
			Send(s_client, buf, recieved, 0);
			fwrite(buf, 1, recieved, cache_file);
		}

				
	cacheTree_add(url);

	fclose(cache_file);
	free(url);
	free(filepath);
	free(buf);
	close(s_server);
	close(s_client);
	return 0;
}

void print_list()
{

	struct cacheTree *ptr = head;
    printf("\n -------Printing list Start------- \n");
    while(ptr != NULL)
    {
        printf("\n -%s- \n",ptr->hash);
		//printf("\n -%ld- \n",ptr->cacheTime);
        ptr = ptr->next;
    }
    printf("\n -------Printing list End------- \n");

    return;
}


/*Timer*/
unsigned int get_current_time(void)
{
    struct timespec ts = {0};

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec + (ts.tv_nsec / 1000000000ULL));
}

/*
=============================================================================
Prefetching
==============================================================================
*/
int read_file(char *host, char *path, void *sock_id, char *serv_port)
{
	//char *buf;
	size_t bufsize;
	int recieved,len,i=0,k,j=0;
	FILE *cached_file;
	char *filepath = (char *)malloc(strlen(CACHE_DIRECTORY) + SHA_DIGEST_LENGTH + 2);
	char *url = (char *)malloc(strlen(host) + strlen(path) + 1);
	char *link;
	char *pre_fetch_url;
	char *pre_fetch_host;
	int c,q1,q2,flag=0;
	char *req1,*req2;
	char prefetch[300][1000];
	char linkpath[300][1000];
	char str[1000] = "\0";
	
	/* construct url */
	url[0] = '\0';
	strcat(url, host);
	strcat(url, path);
	char URLhash[SHA_DIGEST_LENGTH];
	strcpy(URLhash,md5(url));

	/* construct file path */
	filepath[0] = '\0';
	strcat(filepath, CACHE_DIRECTORY);
	strcat(filepath, "/");
	strncat(filepath, URLhash, SHA_DIGEST_LENGTH);
	/* open cache file */
	cached_file = fopen(filepath, "r");


	fseek(cached_file,0,SEEK_END);	
	len=ftell(cached_file);
	rewind(cached_file);

	bufsize=len;

	//buf = malloc(len+1);
	char buftest[len+1];
	char* buf = &buftest[0];

	recieved = fread(buf, bufsize, len, cached_file);

	//int z = 0;
	while (strstr(buf,"<a href=\"")!=NULL)
	{
		
		req1 =strstr(buf,"<a href=\"");
		req1 = req1 + strlen("<a href=\"");
		req2 = strstr(req1,"\"");
	
		strncpy(prefetch[i],req1,(req2-req1));
		//printf("%s\n",prefetch[i]);
		if (prefetch[i][0] == '/' && prefetch[i][1] != '/')
		{
			strcat(str,host);
			strcat(str,prefetch[i]);
			strcpy(linkpath[i],str);
			bzero(str,sizeof str);
			//printf("%s\n",linkpath[i]);
			
		}
		else
		strcpy(linkpath[i],prefetch[i]);
		//printf("%s\n",linkpath[i]);
		
		buf = buf + (req1-buf);
		i++;
	}

	for(j=0; j<=i; j++){
		if( ! (strncmp(linkpath[j], "www",3)) || !(strncmp(linkpath[j], "http",4)) ){
			if(  !(strncmp(linkpath[j], "http",4)) && (strncmp(linkpath[j], "https",5)) ){
				link = malloc(1000);
				link[0] = '\0';
				sscanf(linkpath[j], "http://%s", link);
			}
			if( !(strncmp(linkpath[j], "www",3)) ){
				link = malloc(1000);
				link[0] = '\0';
				strcpy(link,linkpath[j]);
				link[strlen(link)] = '\0';
			}
			printf(">>>%s\n",link);

			pre_fetch_host=(char *)malloc(1000);
			pre_fetch_url=(char *)malloc(1000);
			pre_fetch_host[0] = '\0';
			pre_fetch_url[0] = '\0';
			for(q1=0;q1<strlen(link);q1++){
				
				//pre_fetch_host=realloc(pre_fetch_host,q1+2);
				strncat(pre_fetch_host,&link[q1],1);
				
				if(link[q1+1]=='/'){
					break;
				}
			}

			for(q1=0;q1<strlen(link);q1++){
				if(link[q1]=='/'){
					flag=1;
					q2=q1;
				}
				if(flag){			
				//pre_fetch_url=realloc(pre_fetch_url,q1+2-q2);
				strncat(pre_fetch_url,&link[q1],1);
				}
			}
			flag=0;
			if( strlen(pre_fetch_url)==0 ){
				strcat(pre_fetch_url, "/");
			}
			pre_fetch_host[strlen(pre_fetch_host)] = '\0';
			pre_fetch_url[strlen(pre_fetch_url)] = '\0';
			printf("Host:%s\n",pre_fetch_host);
			printf("URL: %s\n",pre_fetch_url);
			prefetching( sock_id, pre_fetch_host, pre_fetch_url, serv_port);
		}
	}

	fclose(cached_file);
	free(url);
	free(filepath);
	return j;
}

void *prefetching(void *sock_id, char *host, char *url, char *serv_port)
{
  char method[4];    /* strlen("GET")+1 */
  char http_version[9];		/* strlen("HTTP/X.X")+1 */
  void *buf = malloc(BUF_START_SIZE+1);
  size_t bufsize = BUF_START_SIZE;
  int new_s_client =  (int) (intptr_t) sock_id;
  int s_server;
  int GOT_CACHED;
  int length=0, i, recieved, available=BUF_START_SIZE;
  struct addrinfo hints, *servinfo, *p;   

  //pthread_detach(pthread_self());

  bzero(buf, bufsize);

  /* update number of threads currently operating */
  pthread_mutex_lock(&count_lock);
  num_threads++;
  pthread_mutex_unlock(&count_lock);

	/*check if cached or not*/
	if(proxycache_iscached(host,url) ){

		printf(">>>Cache hit!\nPage returned from cached file\n");
		pthread_mutex_lock(&cache_write_lock);
		sem_wait(&cache_read_sem);
		pthread_mutex_unlock(&cache_write_lock);
		sem_post(&cache_read_sem);
		close(new_s_client);
		free(url);
		free(host);
		free(buf);

		pthread_mutex_lock(&count_lock);
		num_threads--;
		pthread_mutex_unlock(&count_lock);
		//pthread_cancel(pthread_self());
		return NULL;

	}

	/* if not cached, send request to the specified host */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

	if ( (getaddrinfo(host, serv_port, &hints, &servinfo)) != 0) 
	{
		send_err(new_s_client, HTTP_ERR_502);
		kill_thread();
		free(url);
		free(host);
		free(buf);
		//pthread_cancel(pthread_self());
		return NULL;
	}

	for(p = servinfo; p != NULL; p = p->ai_next) 
	{
		if ((s_server = socket(p->ai_family, p->ai_socktype,
						p->ai_protocol)) < 0){
			kill_thread();
			//pthread_cancel(pthread_self()); 
			return NULL;
	}
		if (connect(s_server, p->ai_addr, p->ai_addrlen) < 0) 
		{
			close(s_server);
			continue;
		}
		break;
	}
    freeaddrinfo(servinfo);

	if (p == NULL)
	{
		send_err(new_s_client, HTTP_ERR_500);
		kill_thread();
		free(url);
		free(host);
		free(buf);
		//pthread_cancel(pthread_self());
		return NULL;
	}

	strcpy(buf,"GET http://");
	strcat(buf,host);
	strcat(buf,url);
	strcat(buf," HTTP/1.0\r\n\r\n");
	length=strlen(buf);
	//printf("Host:%s\nURL:%s\nBuf:%s\nBufsize:%d\nLength:%d\n",host,url,buf,bufsize,length);
	send_http_request(s_server, host, url, buf, &bufsize, length);	
	printf("prefetching is running\n");
	/* recieve response, and, write webpage to cache. */
	pthread_mutex_lock(&cache_write_lock);
	for (i = 0; i < MAX_NUM_THREADS; i++)
		sem_wait(&cache_read_sem);

	linkcache_addtocache(host, url, s_server, new_s_client, buf, &bufsize);

	for (i = 0; i < MAX_NUM_THREADS; i++)
		sem_post(&cache_read_sem);
	pthread_mutex_unlock(&cache_write_lock);


	free(url);
	free(host);

	pthread_mutex_lock(&count_lock);
	num_threads--;
	pthread_mutex_unlock(&count_lock);

	//pthread_cancel(pthread_self());
	
	return NULL;
}

int linkcache_addtocache(char *host, char *path, int s_server,int s_client, void *buf, size_t *bufsize)
{
	int length=0, available = *bufsize; 
	int recieved;
	FILE *cache_file;
	char *filepath = (char *)malloc(strlen(CACHE_DIRECTORY) + SHA_DIGEST_LENGTH + 2);
	char *url = (char *)malloc(strlen(host) + strlen(path) + 1);
	
	/* construct url */
	url[0] = '\0';
	strcat(url, host);
	strcat(url, path);
	//printf("Prefetch URL %s\n",url);
	char URLhash[SHA_DIGEST_LENGTH]; 
	strcpy(URLhash,md5(url));

	/* construct file path */
	filepath[0] = '\0';
	strcat(filepath, CACHE_DIRECTORY);
	strcat(filepath, "/");
	strncat(filepath, URLhash, SHA_DIGEST_LENGTH);


	cache_file = fopen(filepath, "w");
	if (cache_file == NULL)
		return -1;

	//printf("Filepath is:%s\n",filepath);

		while ( (recieved = recv(s_server, buf, *bufsize, 0)) != 0){
			fwrite(buf, 1, recieved, cache_file);
		}

				
	cacheTree_add(url);

	fclose(cache_file);
	free(url);
	free(filepath);
	free(buf);
	close(s_server);
	close(s_client);
	return 0;
}

