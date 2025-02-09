#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TABLE_SIZE 100

typedef struct Entry {
    char* key;
    char* value;
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
void hashmap_put(HashMap* map, const char* key, const char* value) {
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

int main() {
	// Disable output buffering
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
	
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
		size_t bytes_read;
		while((bytes_read = read(client_sock, req_buf, sizeof(req_buf))))
		{
			printf("req_buf: %s\n", req_buf);
			char *smthing = strtok(req_buf, "\r\n");
			char *smthing2 = strtok(0, "\r\n");
			char *command = strtok(0, "\r\n");
			printf("command: %s\n", command);

			if (strncmp(command, "PING", strlen("PING"))==0)
			{
				write(client_sock, "+PONG\r\n", strlen("+PONG\r\n"));				
			}
			else if (strncmp(command, "ECHO", strlen("ECHO"))==0)
			{
				strtok(0, "$");
				strtok(0, "\r\n");
				char *input = strtok(0, "\r\n");
				input--;
				input[0] = '+';
				input[strlen(input)]='\r';

				write(client_sock, input, strlen(input));
			}
			else if (strncmp(command, "SET", strlen("SET"))==0)
			{
//--------------[ KEY ]---------------------------------------------

				strtok(0, "$");
				strtok(0, "\r\n");
				char *key = strtok(0, "\r\n");
//--------------[ VALUE ]---------------------------------------------
				strtok(0, "$");
				strtok(0, "\r\n");
				char *val = strtok(0, "\r\n");
				val--;
				val[0] = '+';
				val[strlen(val)]='\r';
//--------------[  ]---------------------------------------------

				hashmap_put(map, key, val);
				write(client_sock, "+OK\r\n", strlen("+OK\r\n"));
			}
			else if (strncmp(command, "GET", strlen("GET"))==0)
			{
				strtok(0, "$");
				strtok(0, "\r\n");
				char *key = strtok(0, "\r\n");
				char *val = hashmap_get(map, key);
				if (val)
					write(client_sock, val, strlen(val));
				else
					write(client_sock, "$-1\r\n", strlen("$-1\r\n"));
			}

		}
}		
	}
	
	
	
	close(server_fd);

	return 0;
}
