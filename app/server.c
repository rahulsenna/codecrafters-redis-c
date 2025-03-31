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
#include <fcntl.h>
#include <sys/time.h>
#include <sys/poll.h>

uint64_t get_curr_time(void) 
{
    struct timeval tv;

    gettimeofday(&tv,NULL);
    return (((uint64_t)tv.tv_sec)*1000)+(tv.tv_usec/1000);
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TABLE_SIZE 100

void print_resp(char *buf, size_t len)
{
	printf("-----------[  ");
	for (size_t i = 0; i < len; ++i)
	{
		 if (buf[i] == '\r')
		 	printf("\\r");
		 else if (buf[i] == '\n')
		 	printf("\\n");
		else if(buf[i] == 0)
			printf("*NULL-TERM*");
		else
			printf("%c", buf[i]);
	}
	printf("   ]-----------\n");

}

typedef enum 
{
	TypeString = 0x0,
	TypeStream,
	TypeCount,
} EntryType;

typedef struct StreamEntry
{
	uint64_t ms_time;
	int sequence_num;
	char *str;
    struct StreamEntry* next;
} StreamEntry;

typedef struct Entry {
    char* key;
    char* value;
	uint64_t expiry;
    struct Entry* next;
	EntryType type;
	StreamEntry* stream;  // For TypeStream entries
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
void hashmap_put(HashMap* map, const char* key, const char* value, uint64_t expiry, EntryType type) {
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
	newEntry->type = type;
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
	ArgReplicationHost,
	ArgCount,
} ArgType;

char *config[ArgCount] = {0};

int read_rdb_file(char *redis_file_path, HashMap* map, char *keys[100])
{
	FILE *rdbfile = fopen(redis_file_path, "rb");
	if (rdbfile == 0)
		return 0;
	unsigned char buffer[1024 * 10];
	size_t bytes_read = fread(buffer, sizeof(unsigned char), 1024 * 10, rdbfile);
	printf("bytes_read: %lu\n", bytes_read);

	int byte_idx = 0;
	while(buffer[byte_idx] != 0xfb)
		byte_idx++;

	int db_map_size = (int)buffer[byte_idx + 1];
	int db_expiry_map_size = (int)buffer[byte_idx + 2];

	byte_idx+=3; // skip 2 bytes of size info

	char value[256];
	char timestamp_str[256];
	for (int i = 0; i < db_map_size; ++i)
	{

		uint64_t timestamp = 0;
		if (i < db_expiry_map_size)
		{
			uint8_t exp_type= buffer[byte_idx++];
			if (exp_type == 0xFC)
			{
				byte_idx += 8;
				snprintf(timestamp_str, sizeof(timestamp_str),
						 "%02X%02X%02X%02X%02X%02X%02X%02X",
						 buffer[byte_idx - 1], buffer[byte_idx - 2], buffer[byte_idx - 3], buffer[byte_idx - 4],
						 buffer[byte_idx - 5], buffer[byte_idx - 6], buffer[byte_idx - 7], buffer[byte_idx - 8]);
				timestamp = strtoull(timestamp_str, NULL, 16);
			}
			else if (exp_type == 0xFD)
			{
				byte_idx += 4;
				snprintf(timestamp_str, sizeof(timestamp_str),
						 "%02X%02X%02X%02X%02X%02X%02X%02X",
						 0, 0, 0, 0,
						 buffer[byte_idx - 1], buffer[byte_idx - 2], buffer[byte_idx - 3], buffer[byte_idx - 4]);
				timestamp = strtoull(timestamp_str, NULL, 16) *1000ULL;
			}
		}
				 
		uint8_t encoding = buffer[byte_idx++]; // encodings 0=string
		

		//--------[ Key ]--------------------------------------------------------------
		int key_len = (int)buffer[byte_idx++];
		char *key = malloc(sizeof(char)*key_len);
		strncpy(key, (char *)buffer + byte_idx, key_len);

		//--------[ Value ]--------------------------------------------------------------
		byte_idx += key_len;
		int val_len = (int)buffer[byte_idx++];
		strncpy(value, (char *)buffer + byte_idx, val_len);
		value[val_len]=0;

		if (timestamp && timestamp > get_curr_time())
		{
			hashmap_put(map, key, value, timestamp, TypeString);
		}
		else if (timestamp == 0)
		{
			hashmap_put(map, key, value, UINT64_MAX, TypeString);
		}
		keys[i] = key;
			
		byte_idx += val_len;
	}

	fclose(rdbfile);
	return db_map_size;
}


int db_map_size, replication_port, port;
HashMap* map;

void *handshake()
{
	struct sockaddr_in master_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(replication_port),
		.sin_addr.s_addr = INADDR_ANY,
	};
	int sock = socket(AF_INET, SOCK_STREAM, 0);

	if (connect(sock, (struct sockaddr *)&master_addr, sizeof(master_addr)) == -1)
	{
		perror("Connect Failed\n");
		return 0;
	}
	size_t bytes_read;
	write(sock, "*1\r\n$4\r\nPING\r\n", strlen("*1\r\n$4\r\nPING\r\n"));
	char buf[1024];
	bytes_read = read(sock, buf, sizeof(buf));
	if (strncmp(buf, "+PONG\r\n", strlen("+PONG\r\n")) != 0)
	{
		perror("Pong Failed\n");
		return 0;
	}
	write(sock, 
		"*3\r\n$8\r\nREPLCONF\r\n$14\r\nlistening-port\r\n$4\r\n6380\r\n",
		strlen("*3\r\n$8\r\nREPLCONF\r\n$14\r\nlistening-port\r\n$4\r\n6380\r\n")
	);

	bytes_read = read(sock, buf, sizeof(buf));
	if (strncmp(buf, "+OK\r\n", strlen("+OK\r\n")) != 0)
	{
		perror("REPLCONF 1 Failed\n");
		return 0;
	}

	write(sock,
		"*3\r\n$8\r\nREPLCONF\r\n$4\r\ncapa\r\n$6\r\npsync2\r\n",
		strlen("*3\r\n$8\r\nREPLCONF\r\n$4\r\ncapa\r\n$6\r\npsync2\r\n")
	);

	bytes_read = read(sock, buf, sizeof(buf));
	if (strncmp(buf, "+OK\r\n", strlen("+OK\r\n")) != 0)
	{
		perror("REPLCONF 2 Failed\n");
		return 0;
	}

	write(sock,
		  "*3\r\n$5\r\nPSYNC\r\n$1\r\n?\r\n$2\r\n-1\r\n",
		  strlen("*3\r\n$5\r\nPSYNC\r\n$1\r\n?\r\n$2\r\n-1\r\n"));

	bytes_read = read(sock, buf, sizeof(buf));
	char *rdb_preamble = strstr(buf, "$");
	
	if (rdb_preamble == 0)
	{
		bytes_read = read(sock, buf, sizeof(buf));
		rdb_preamble = buf;
	}
	size_t rdb_file_bytes;
	sscanf(rdb_preamble, "$%lu", &rdb_file_bytes);
	printf("rdb_file_bytes: %lu\n", rdb_file_bytes);

	char *rdb_buffer = strstr(rdb_preamble, "\n") + 1;

	size_t end_rdb_buffer = (rdb_buffer+rdb_file_bytes) - buf;
	
	printf("end_rdb_buffer: %lu\n", end_rdb_buffer);
	printf("bytes_read: %lu\n", bytes_read);

	if (end_rdb_buffer < bytes_read)
	{
		snprintf(buf, sizeof(buf), "%s", buf+end_rdb_buffer);
		bytes_read -= end_rdb_buffer;
	} else
	{
		bytes_read = read(sock, buf, sizeof(buf));
	}
	
	char out[1024];
	size_t total_bytes = 0;
	while(1)
	{
		do
		{
			if (bytes_read == 0)
				break;
			total_bytes += bytes_read;
			char *token, *saveptr;
			char *chr_cnt = strtok_r(buf, "\r\n", &saveptr);
			size_t distance;
			do
			{
				size_t mypos = chr_cnt- buf;
				size_t bytes_yet_to_read = bytes_read-mypos;
				int query_cnt = atoi(chr_cnt + 1);
				char *tokens[10];
				for (int i = 0; i < query_cnt; ++i)
				{
					chr_cnt = strtok_r(0, "\r\n", &saveptr);
					token = strtok_r(0, "\r\n", &saveptr);
					tokens[i] = token;
				}

				char *command = tokens[0];

				if (strncmp(command, "SET", strlen("SET")) == 0)
				{
					uint64_t expiry_time = UINT64_MAX;
					if (tokens[3] && strncmp(tokens[3], "px", strlen("px")) == 0)
					{
						uint64_t curr_time = get_curr_time();
						expiry_time = curr_time + atoll(tokens[4]);
					}
					hashmap_put(map, tokens[1], tokens[2], expiry_time, TypeString);
				} else if (strncmp(command, "REPLCONF", strlen("REPLCONF")) == 0)
				{
					size_t total_processed_bytes = total_bytes-bytes_yet_to_read;
					size_t n = total_processed_bytes;
					int dig = 0;
					do
					{
						n /=10;
						dig++;
					} while (n > 0);

					snprintf(out, sizeof(out),
							 "*3\r\n$8\r\nREPLCONF\r\n$3\r\nACK\r\n$%d\r\n%lu\r\n",
							 dig,
							 total_processed_bytes);
					write(sock, out, strlen(out));
				}
				chr_cnt = strtok_r(0, "\r\n", &saveptr);
				distance = chr_cnt - buf;
			} while (chr_cnt && distance < bytes_read);
		} while ((bytes_read = read(sock, buf, sizeof(buf))));
	}

	close(sock);

	return 0;
}

#include <pthread.h>
char *keys[100];
int replica_socks[10] = {0};
int replica_socks_cnt = 0;
int did_propogate_to_replica = 0;
void *handle_client(void *arg)
{
	int client_sock = *(int *)arg;
    free(arg);
    printf("Client connected - port: %d - client_sock: %d\n", port, client_sock);


    char req_buf[1024];
    char req_buf2[1024];
    char output_buf[1024];
    size_t bytes_read;
	int is_multi = 0;
	while((bytes_read = read(client_sock, req_buf, sizeof(req_buf))))
	{
		memcpy(req_buf2, req_buf, 1024);
		char *query = req_buf + 1;
		char *saveptr;  // Save pointer for the outer tokenization
		int query_cnt = atoi(strtok_r(query, "\r\n", &saveptr));
		char *tokens[10];
		for (int i = 0; i < query_cnt; ++i)
		{
			char *chr_cnt = strtok_r(NULL, "\r\n", &saveptr);
			char *token = strtok_r(NULL, "\r\n", &saveptr);
			tokens[i] = token;
			printf("%d tokens[%d]: %s | ", port, i, tokens[i]);
		}
		printf("\n");

		char *command = tokens[0];
		for (char *c = command; *c; ++c)
			*c = toupper(*c);

		if (strncmp(command, "PING", strlen("PING")) == 0)
		{
			snprintf(output_buf, sizeof(output_buf), "+PONG\r\n");
		}
		else if (strncmp(command, "ECHO", strlen("ECHO")) == 0)
		{
			snprintf(output_buf, sizeof(output_buf), "+%s\r\n", tokens[1]);
		}
		else if (strncmp(command, "SET", strlen("SET")) == 0)
		{
			uint64_t expiry_time = UINT64_MAX;
			if (tokens[3] && strncmp(tokens[3], "px", strlen("px")) == 0)
			{
				uint64_t curr_time = get_curr_time();
				expiry_time = curr_time + atoll(tokens[4]);
			}

			hashmap_put(map, tokens[1], tokens[2], expiry_time, TypeString);
			snprintf(output_buf, sizeof(output_buf), "+OK\r\n");

			did_propogate_to_replica = replica_socks_cnt;
			for (int i = 0; i < replica_socks_cnt; ++i)
			{
				write(replica_socks[i], req_buf2, strlen(req_buf2)); 
			}
		}
		else if (strncmp(command, "GET", strlen("GET")) == 0)
		{
			Entry *val = hashmap_get_entry(map, tokens[1]);

			if (val && val->expiry > get_curr_time())
			{
				snprintf(output_buf, sizeof(output_buf), "+%s\r\n", val->value);
			}
			else
				snprintf(output_buf, sizeof(output_buf), "$-1\r\n");
		}
		else if (strncmp(command, "INCR", strlen("INCR")) == 0)
		{
			Entry *val = hashmap_get_entry(map, tokens[1]);

			if (val)
			{
				int num = INT_MIN;
				sscanf(val->value, "%d", &num);
				if (num == INT_MIN)
				{
					snprintf(output_buf, sizeof(output_buf), "-ERR value is not an integer or out of range\r\n");
				} else
				{
					num++;
					free(val->value);
					char num_str[10];
					snprintf(num_str, sizeof(num_str), "%d", num);
					val->value = strdup(num_str);
					snprintf(output_buf, sizeof(output_buf), ":%d\r\n", num);	
				}
			} else
			{
				hashmap_put(map, tokens[1], "1", UINT64_MAX, TypeString);
				snprintf(output_buf, sizeof(output_buf), ":1\r\n");
			}
		}

		else if (strncmp(command, "CONFIG", strlen("CONFIG")) == 0)
		{
			if (strncmp(tokens[1], "GET", strlen("GET")) == 0)
			{
				if (strncmp(tokens[2], "dir", strlen("dir")) == 0)
				{
					snprintf(output_buf, sizeof(output_buf), "*2\r\n$%lu\r\n%s\r\n$%lu\r\n%s\r\n",
							 strlen("dir"), "dir",
							 strlen(config[ArgDirName]), config[ArgDirName]);
				}
			}
		}
		else if (strncmp(command, "KEYS", strlen("KEYS")) == 0)
		{
			snprintf(output_buf, sizeof(output_buf), "*%d\r\n", db_map_size);
			for (int i = 0; i < db_map_size; ++i)
			{
				snprintf(output_buf, sizeof(output_buf), "%s$%lu\r\n%s\r\n", output_buf, strlen(keys[i]), keys[i]);
			}
		}
		else if ((strncmp(command, "INFO", strlen("INFO")) == 0))
		{
			if (replication_port == 0)
			{
				snprintf(output_buf, sizeof(output_buf),
						 "$%lu\r\n"
						 "role:master\r\n"
						 "master_replid:8371b4fb1155b71f4a04d3e1bc3e18c4a990aeeb\r\n"
						 "master_repl_offset:0"
						 "\r\n",
						 strlen(
							 "role:master\r\n"
							 "master_replid:8371b4fb1155b71f4a04d3e1bc3e18c4a990aeeb\r\n"
							 "master_repl_offset:0"));
			}
			else
				snprintf(output_buf, sizeof(output_buf), "$10\r\nrole:slave\r\n");
		}
		else if ((strncmp(command, "REPLCONF", strlen("REPLCONF")) == 0))
		{
			snprintf(output_buf, sizeof(output_buf), "+OK\r\n");
		}
		else if ((strncmp(command, "PSYNC", strlen("PSYNC")) == 0))
		{
			snprintf(output_buf, sizeof(output_buf), "+FULLRESYNC 8371b4fb1155b71f4a04d3e1bc3e18c4a990aeeb 0\r\n");
			write(client_sock, output_buf, strlen(output_buf));
			write(client_sock,
				  "$88\r\n\x52\x45\x44\x49\x53\x30\x30\x31\x31\xfa\x09\x72\x65\x64\x69\x73\x2d\x76\x65\x72\x05\x37\x2e\x32\x2e\x30\xfa\x0a\x72\x65\x64\x69\x73\x2d\x62\x69\x74\x73\xc0\x40\xfa\x05\x63\x74\x69\x6d\x65\xc2\x6d\x08\xbc\x65\xfa\x08\x75\x73\x65\x64\x2d\x6d\x65\x6d\xc2\xb0\xc4\x10\x00\xfa\x08\x61\x6f\x66\x2d\x62\x61\x73\x65\xc0\x00\xff\xf0\x6e\x3b\xfe\xc0\xff\x5a\xa2",
				  88 + 5);
			replica_socks[replica_socks_cnt++] = client_sock;
			printf("replica_sock: %d\n", client_sock);
			return 0;
		}
		else if ((strncmp(command, "WAIT", strlen("WAIT")) == 0))
		{
			if (did_propogate_to_replica == 0)
			{ 
				snprintf(output_buf, sizeof(output_buf), ":%d\r\n", replica_socks_cnt);
				write(client_sock, output_buf, strlen(output_buf));
				continue;
			}

			int timeout_ms = atoi(tokens[2]);
			int min_replica_processed_cnt = atoi(tokens[1]);

			printf("replica_socks_cnt: %d\n", replica_socks_cnt);
			printf("min_replica_processed_cnt: %d\n", min_replica_processed_cnt);

			char buf[1024];
			int out = 0;
			const char *getack_cmd = "*3\r\n$8\r\nREPLCONF\r\n$6\r\nGETACK\r\n$1\r\n*\r\n";

			// Send GETACK to all replicas
			for (int i = 0; i < replica_socks_cnt; ++i)
			{
				ssize_t sent = send(replica_socks[i], getack_cmd, strlen(getack_cmd), MSG_DONTWAIT);
				if (sent < 0)
				{
					perror("Send failed");
				}
			}

			struct pollfd fds[10];
			for (int i = 0; i < replica_socks_cnt; ++i)
			{
				fds[i].fd = replica_socks[i];
				fds[i].events = POLLIN; // We only care about incoming data
			}

			struct timeval start_time, current_time;
			gettimeofday(&start_time, NULL);
		
			while (1)
			{
				gettimeofday(&current_time, NULL);
				long elapsed_ms = (current_time.tv_sec - start_time.tv_sec) * 1000 +
								  (current_time.tv_usec - start_time.tv_usec) / 1000;
				long remaining_ms = timeout_ms - elapsed_ms;

				if (remaining_ms <= 0)
				{
					printf("Total timeout reached, stopping polling.\n");
					break;
				}

				int activity = poll(fds, replica_socks_cnt, remaining_ms);
				if (activity > 0)
				{
					// Check which sockets have data
					for (int i = 0; i < replica_socks_cnt; ++i)
					{
						if (fds[i].revents & POLLIN)
						{
							read(fds[i].fd, buf, sizeof(buf) - 1);
							out++;
						}
					}
				}
			}
			snprintf(output_buf, sizeof(output_buf), ":%d\r\n", out);
		}
		else if ((strncmp(command, "TYPE", strlen("TYPE")) == 0))
		{
			Entry *val = hashmap_get_entry(map, tokens[1]);
			if (val)
			{
				if (val->type == TypeString)
					snprintf(output_buf, sizeof(output_buf), "+string\r\n");
				else if (val->type == TypeStream)
					snprintf(output_buf, sizeof(output_buf), "+stream\r\n");
			} else
			{	
				snprintf(output_buf, sizeof(output_buf), "+none\r\n");
			}
		}
		else if ((strncmp(command, "XADD", strlen("XADD")) == 0))
		{
			char *entry_key = tokens[1];
			char* ID = tokens[2];
			uint64_t ms_time;
			int sequence_num;
			char *stream_key = tokens[3];
			char *stream_val = tokens[4];

			if (strncmp(ID, "*", 2) == 0)
			{
				sequence_num = 0;
				ms_time = get_curr_time();
			}
			else
			{
				sscanf(ID, "%llu-%d", &ms_time, &sequence_num);
				char sequence_char;
				sscanf(ID, "%*llu-%c", &sequence_char);
				if (sequence_char == '*')
					sequence_num = -1;
			}

			if (ms_time == 0 && sequence_num == 0)
			{
				snprintf(output_buf, sizeof(output_buf), "-ERR The ID specified in XADD must be greater than 0-0\r\n");
				write(client_sock, output_buf, strlen(output_buf));
				continue;
			}

			char stream_str[256];
			Entry *val = hashmap_get_entry(map, entry_key);
			char stream_resp[1024];
			if (val == 0)
			{
				if (sequence_num == -1)
					sequence_num = (ms_time ? 0 : 1);
				
				snprintf(stream_str, sizeof(stream_str),
								 "%llu-%d %s:%s\n", ms_time, sequence_num, stream_key, stream_val);
				char new_id[256];
				snprintf(new_id, sizeof(new_id),"%llu-%d", ms_time, sequence_num);
				
				snprintf(output_buf, sizeof(output_buf), "$%lu\r\n%s\r\n", strlen(new_id), new_id);	
				hashmap_put(map, entry_key, stream_str, UINT64_MAX, TypeStream);
				
				snprintf(stream_resp, sizeof(stream_resp), "*2\r\n$%lu\r\n%s\r\n*%d\r\n", strlen(new_id), new_id, query_cnt - 3);
				for (int i = 3; i < query_cnt; ++i)
					snprintf(stream_resp, sizeof(stream_resp), "%s$%lu\r\n%s\r\n", stream_resp, strlen(tokens[i]), tokens[i]);

				val = hashmap_get_entry(map, entry_key);
				val->stream = calloc(1, sizeof(StreamEntry));
				val->stream->ms_time = ms_time;
				val->stream->sequence_num = sequence_num;
				val->stream->str = strdup(stream_resp);
				val->stream->next = 0;

			} else
			{
				uint64_t last_ms_time;
				int last_sequence_num;
				sscanf(val->value, "%llu-%d", &last_ms_time, &last_sequence_num);

				if (sequence_num == -1)
				{
					if (ms_time == last_ms_time)
						sequence_num = last_sequence_num + 1;
					else
						sequence_num = 0;
				}
				
				snprintf(stream_str, sizeof(stream_str),
					"%llu-%d %s:%s\n", ms_time, sequence_num, stream_key, stream_val);

				if (ms_time > last_ms_time || (ms_time == last_ms_time && sequence_num > last_sequence_num))
				{
					char new_id[256];
					snprintf(new_id, sizeof(new_id),"%llu-%d", ms_time, sequence_num);

					snprintf(output_buf, sizeof(output_buf), "$%lu\r\n%s\r\n", strlen(new_id), new_id);
					if (val->value)
						free(val->value);
					val->value = strdup(stream_str);

					StreamEntry *stream_entry = val->stream;
					while(stream_entry->next)
					{
						stream_entry = stream_entry->next;
					}

					snprintf(stream_resp, sizeof(stream_resp), "*2\r\n$%lu\r\n%s\r\n*%d\r\n", strlen(new_id), new_id, query_cnt - 3);
					for (int i = 3; i < query_cnt; ++i)
						snprintf(stream_resp, sizeof(stream_resp), "%s$%lu\r\n%s\r\n", stream_resp, strlen(tokens[i]), tokens[i]);

					stream_entry->next = calloc(1, sizeof(StreamEntry));
					stream_entry = stream_entry->next;
					stream_entry->ms_time = ms_time;
					stream_entry->sequence_num = sequence_num;
					stream_entry->str = strdup(stream_resp);
					stream_entry->next = 0;
				} else
				{
					snprintf(output_buf, sizeof(output_buf), "-ERR The ID specified in XADD is equal or smaller than the target stream top item\r\n");
				}
			}
		}
		else if ((strncmp(command, "XRANGE", strlen("XRANGE")) == 0))
		{
			
			char *stream_key = tokens[1];
			uint64_t start_time, end_time;
			int start_seq, end_seq = INT_MAX;
			sscanf(tokens[2], "%llu-%d", &start_time, &start_seq);
			sscanf(tokens[3], "%llu-%d", &end_time, &end_seq);
			
			output_buf[0] = '\0';

			Entry *entry = hashmap_get_entry(map, stream_key);
			StreamEntry *stream_entry = entry->stream;
			int matching_entries = 0;
			while (stream_entry)
			{
				if ((stream_entry->ms_time >= start_time && stream_entry->sequence_num >= start_seq) &&
					(stream_entry->ms_time <= end_time && stream_entry->sequence_num <= end_seq))
				{
					matching_entries++;
					snprintf(output_buf, sizeof(output_buf), "%s%s", output_buf, stream_entry->str);
				}
				stream_entry = stream_entry->next;
			}

			snprintf(output_buf, sizeof(output_buf), "*%d\r\n%s", matching_entries, output_buf);
		}
		else if ((strncmp(command, "XREAD", strlen("XREAD")) == 0))
		{
			int stream_count = (query_cnt - 2) / 2;

			char *stream_keys[100];
			char *IDs[100];
			int token_idx = 2;
			int blocking = 0;
			useconds_t block_ms;
			if ((strncmp(tokens[1], "block", strlen("block")) == 0))
			{
				blocking = 1;
				stream_count -= 1;
				token_idx = 4;

				sscanf(tokens[2], "%u", &block_ms);
				block_ms *= 1000;
				usleep(block_ms);
			}

			for (int i = 0; i < stream_count; ++i)
				stream_keys[i] = tokens[token_idx++];

			for (int i = 0; i < stream_count; ++i)
				IDs[i] = tokens[token_idx++];

			int things_added = 0;
			do
			{
				int only_new_entries = 0;
				snprintf(output_buf, sizeof(output_buf), "*%d\r\n", stream_count);
				for (int i = 0; i < stream_count; ++i)
				{
					char *stream_key = stream_keys[i];
					Entry *entry = hashmap_get_entry(map, stream_key);
					uint64_t entry_time;
					int entry_seq;

					snprintf(output_buf, sizeof(output_buf), "%s*2\r\n$%lu\r\n%s\r\n", output_buf, strlen(stream_key), stream_key);

					sscanf(IDs[i], "%llu-%d", &entry_time, &entry_seq);
					if (entry_time == 0 && entry_seq == 0 && strcmp(IDs[i], "$") == 0)
					{
						only_new_entries = 1;
						entry_seq = INT_MAX;
						entry_time = UINT64_MAX;
					}

					StreamEntry *stream_entry = entry->stream;
					while (stream_entry)
					{
						if (stream_entry->ms_time > entry_time ||
							(stream_entry->ms_time == entry_time && stream_entry->sequence_num > entry_seq))
						{
							things_added++;
							snprintf(output_buf, sizeof(output_buf), "%s*1\r\n%s", output_buf, stream_entry->str);
							if (blocking && block_ms == 0)
								goto end_xread_proc;
						}
						if (only_new_entries && stream_entry->next == 0)
						{
							entry_seq = stream_entry->sequence_num;
							entry_time = stream_entry->ms_time;
							only_new_entries = 0;
						}
						stream_entry = stream_entry->next;
					}
				}
			} while (blocking && block_ms == 0);

		end_xread_proc:
			if (blocking && things_added == 0)
				snprintf(output_buf, sizeof(output_buf), "$-1\r\n");
		}

		else if (strncmp(command, "MULTI", strlen("MULTI")) == 0)
		{
			is_multi = 1;
			snprintf(output_buf, sizeof(output_buf), "+OK\r\n");
		}
		write(client_sock, output_buf, strlen(output_buf));
	}

	close(client_sock);
	return NULL;
}

int main(int argc, char *argv[]) {
	// Disable output buffering
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	for (int i = 0; i < ArgCount; ++i)
	{
		config[i] = 0;
	}

	port = 6379;
	replication_port = 0;

	for (int i = 1; i < argc; i+=2)
	{
		if (strncmp(argv[i], "--replicaof", strlen("--replicaof")) == 0)
		{
			config[ArgReplicationHost] = argv[i + 1];
			sscanf(argv[i + 1], "%*s %d", &replication_port);
		}
		if (strncmp(argv[i], "--port", strlen("--port")) == 0)
		{
			port = atoi(argv[i+1]);
		}
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

	map = hashmap_create();

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
									 .sin_port = htons(port),
									 .sin_addr = { htonl(INADDR_ANY) },
									};
	
	if (bind(server_fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) != 0) {
		printf("Bind failed: %s \n", strerror(errno));
		return 1;
	}
	
	if (replication_port)
	{
		pthread_t handshake_thread_id;
		if (pthread_create(&handshake_thread_id, NULL, handshake, 0) != 0)
		{
			perror("Thread creation failed");
		}
		pthread_detach(handshake_thread_id);
	}	
	int connection_backlog = 5;
	if (listen(server_fd, connection_backlog) != 0) {
		printf("Listen failed: %s \n", strerror(errno));
		return 1;
	}
	
	printf("Waiting for a client to connect...\n");
	client_addr_len = sizeof(client_addr);
	


	char redis_file_path[1024];
	snprintf(redis_file_path, sizeof(redis_file_path), "%s/%s", config[ArgDirName], config[ArgFileName]);
	

	db_map_size = read_rdb_file(redis_file_path, map, keys);
    
	while(1)
	{
		int client_sock = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
		if (client_sock == -1)
		{ 
			perror("Accept Failed\n");
			continue;
		}

		// Pass client socket to thread
		int *client_sock_ptr = malloc(sizeof(int));
		*client_sock_ptr = client_sock;

		pthread_t thread_id;
		if (pthread_create(&thread_id, NULL, handle_client, client_sock_ptr) != 0)
		{
			perror("Thread creation failed");
			close(client_sock);
			free(client_sock_ptr);
			continue;
		}

		// Detach the thread to auto-cleanup when done
		pthread_detach(thread_id);
	}
	
	
	
	close(server_fd);
       
	return 0;
}
