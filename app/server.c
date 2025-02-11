#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <limits.h>

#include<sys/time.h>

long long get_curr_time(void) 
{
    struct timeval tv;

    gettimeofday(&tv,NULL);
    return (((long long)tv.tv_sec)*1000)+(tv.tv_usec/1000);
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TABLE_SIZE 100

typedef struct Entry {
    char* key;
    char* value;
	long long expiry;
    struct Entry* next;
} Entry;

typedef struct HashMap {
    Entry* table[TABLE_SIZE];
} HashMap;

// Hash function using djb2 algorithm
unsigned int hash(const char* str) {
    unsigned int hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash % TABLE_SIZE;
}

// Create new hashmap
HashMap* hashmap_create() {
    HashMap* map = (HashMap*)malloc(sizeof(HashMap));
    if (map == NULL) return NULL;
    
    for (int i = 0; i < TABLE_SIZE; i++) {
        map->table[i] = NULL;
    }
    return map;
}

// Insert or update key-value pair
void hashmap_put(HashMap* map, const char* key, const char* value, long long expiry) {
    unsigned int index = hash(key);
    Entry* current = map->table[index];
    
    // Check if key already exists
    while (current != NULL) {
        if (strcmp(current->key, key) == 0) {
            // Update value
            free(current->value);
            current->value = strdup(value);
            return;
        }
        current = current->next;
    }
    
    // Create new entry
    Entry* newEntry = (Entry*)malloc(sizeof(Entry));
    if (newEntry == NULL) return;
    
    newEntry->key = strdup(key);
    newEntry->value = strdup(value);
	newEntry->expiry = expiry;
    newEntry->next = map->table[index];
    map->table[index] = newEntry;
}

// Get value by key
char* hashmap_get(HashMap* map, const char* key) {
    unsigned int index = hash(key);
    Entry* current = map->table[index];
    
    while (current != NULL) {
        if (strcmp(current->key, key) == 0) {
            return current->value;
        }
        current = current->next;
    }
    return NULL;
}

Entry* hashmap_get_entry(HashMap* map, const char* key)
{
    unsigned int index = hash(key);
    Entry* current = map->table[index];
    
    while (current != NULL)
	{
        if (strcmp(current->key, key) == 0)
		{
            return current;
        }
        current = current->next;
    }
    return NULL;
}

// Remove key-value pair
void hashmap_remove(HashMap* map, const char* key) {
    unsigned int index = hash(key);
    Entry* current = map->table[index];
    Entry* prev = NULL;
    
    while (current != NULL) {
        if (strcmp(current->key, key) == 0) {
            if (prev == NULL) {
                map->table[index] = current->next;
            } else {
                prev->next = current->next;
            }
            free(current->key);
            free(current->value);
            free(current);
            return;
        }
        prev = current;
        current = current->next;
    }
}

// Free hashmap and all entries
void hashmap_free(HashMap* map) {
    for (int i = 0; i < TABLE_SIZE; i++) {
        Entry* current = map->table[i];
        while (current != NULL) {
            Entry* next = current->next;
            free(current->key);
            free(current->value);
            free(current);
            current = next;
        }
    }
    free(map);
}

typedef enum 
{
	ArgDirName = 0x0,
	ArgFileName,
	ArgCount,
} ArgType;

char *config[ArgCount] = {0};


int main(int argc, char *argv[]) {
	// Disable output buffering
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	for (int i = 0; i < ArgCount; ++i)
	{
		config[i] = 0;
	}
	for (int i = 1; i < argc; i+=2)
	{
		if (strncmp(argv[i], "--dir", strlen("--dir")) == 0)
		{
			config[ArgDirName] = argv[i+1];
		}

		if (strncmp(argv[i], "--dbfilename", strlen("--dbfilename")) == 0)
		{
			config[ArgFileName] = argv[i+1];
		}
	}

	printf("Config[ArgDirName]: %s\n", config[ArgDirName]);
	printf("Config[ArgFileName]: %s\n", config[ArgFileName]);
	
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	printf("Logs from your program will appear here!\n");

	// Uncomment this block to pass the first stage
	//
	int server_fd;
	struct sockaddr_in client_addr;
	socklen_t client_addr_len;
	//
	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd == -1) {
		printf("Socket creation failed: %s...\n", strerror(errno));
		return 1;
	}
	
	// Since the tester restarts your program quite often, setting SO_REUSEADDR
	// ensures that we don't run into 'Address already in use' errors
	int reuse = 1;
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
		printf("SO_REUSEADDR failed: %s \n", strerror(errno));
		return 1;
	}
	
	struct sockaddr_in serv_addr = { .sin_family = AF_INET ,
									 .sin_port = htons(6379),
									 .sin_addr = { htonl(INADDR_ANY) },
									};
	
	if (bind(server_fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) != 0) {
		printf("Bind failed: %s \n", strerror(errno));
		return 1;
	}
	
	int connection_backlog = 5;
	if (listen(server_fd, connection_backlog) != 0) {
		printf("Listen failed: %s \n", strerror(errno));
		return 1;
	}
	
	printf("Waiting for a client to connect...\n");
	client_addr_len = sizeof(client_addr);

	HashMap* map = hashmap_create();

	while(1)
	{
		int client_sock = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
		if (client_sock == -1)
		{ 
			perror("Accept Failed\n");
			continue;
		}
if (fork()==0)
{
		printf("Client connected\n");
		
		char req_buf[1024];
		char output_buf[1024];
		size_t bytes_read;
		while((bytes_read = read(client_sock, req_buf, sizeof(req_buf))))
		{
			char *query = req_buf+1;
			int query_cnt = atoi(strtok(query, "\r\n"));
			char *tokens[10];
			for (int i = 0; i < query_cnt; ++i)
			{
				 char *chr_cnt = strtok(0, "\r\n");
				 char *token = strtok(0, "\r\n");
				 tokens[i] = token;
				 printf("tokens[%d]: %s\n",i, tokens[i]);
			}

			char *command = tokens[0];
			if (strncmp(command, "PING", strlen("PING"))==0)
			{
				write(client_sock, "+PONG\r\n", strlen("+PONG\r\n"));				
			}
			else if (strncmp(command, "ECHO", strlen("ECHO"))==0)
			{
				snprintf(output_buf, sizeof(output_buf), "+%s\r\n", tokens[1]);
				write(client_sock, output_buf, strlen(output_buf));
			}
			else if (strncmp(command, "SET", strlen("SET")) == 0)
			{
				write(client_sock, "+OK\r\n", strlen("+OK\r\n"));
				long long expiry_time = INT64_MAX;
				if (tokens[3] && strncmp(tokens[3], "px", strlen("px"))==0)
				{
					long long curr_time = get_curr_time();
					expiry_time = curr_time+atoll(tokens[4]);
				}

				hashmap_put(map, tokens[1], tokens[2], expiry_time);
			}
			else if (strncmp(command, "GET", strlen("GET"))==0)
			{
				Entry *val = hashmap_get_entry(map, tokens[1]);
				
				if (val && val->expiry > get_curr_time())
				{
					snprintf(output_buf, sizeof(output_buf), "+%s\r\n", val->value);
					write(client_sock, output_buf, strlen(output_buf));	
				}
				else
					write(client_sock, "$-1\r\n", strlen("$-1\r\n"));
			}
			else if (strncmp(tokens[0], "CONFIG", strlen("CONFIG"))==0)
			{
				if (strncmp(tokens[1], "GET", strlen("GET"))==0)
				{
					if (strncmp(tokens[2], "dir", strlen("dir"))==0)
					{
						snprintf(output_buf, sizeof(output_buf), "*2\r\n$%lu\r\n%s\r\n$%lu\r\n%s\r\n",
								 strlen("dir"), "dir",
								 strlen(config[ArgDirName]), config[ArgDirName]);

						write(client_sock, output_buf, strlen(output_buf));	

					}
				}
			}

		}
}
	close(client_sock);
	}
	
	
	
	close(server_fd);

	return 0;
}
