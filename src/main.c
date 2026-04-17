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
#include <poll.h>
#include <pthread.h>
#include <math.h>
#include <stdint.h>
#include "sha256.h"

#include <sys/stat.h>
#include <sys/types.h>

#define STB_DS_IMPLEMENTATION
#include "stb_ds.h"

typedef struct ConfigMap
{
  char* key;
  char* value;
} ConfigMap;

ConfigMap* config = NULL;

#include "String.h"

#define MAX_TOKEN_COUNT 16
typedef struct Resp
{
  String tokens[MAX_TOKEN_COUNT];
  uint32_t len;
} Resp;

typedef struct Transaction
{
  Resp** data;
  uint32_t len;
  uint32_t cap;
  uint8_t active;
} Transaction;

Transaction init_transaction()
{
  Transaction t = { 0 };
  t.cap = 10;
  t.len = 0;
  t.active = 0;
  t.data = (Resp**) malloc(sizeof(Resp*) * t.cap);
  return t;
}

Resp* deep_cpy_resp(Resp* cmd)
{
  Resp* out = (Resp*) malloc(sizeof(Resp));
  out->len = cmd->len;
  for (size_t i = 0; i < out->len; ++i)
  {
    out->tokens[i] = _str_cpy(PSTR(cmd->tokens[i]), LSTR(cmd->tokens[i]));
  }
  return out;
}

void push_transaction(Transaction* t, Resp* cmd)
{
  if ((t->len + 1) > t->cap)
  {
    t->cap *= 2;
    t->data = (Resp**) realloc(t->data, sizeof(Resp*) * t->cap);
  }
  t->data[t->len++] = deep_cpy_resp(cmd);
}

void free_resp(Resp* r)
{
  if (!r) return;

  for (size_t i = 0; i < r->len; ++i)
  {
    STR_FREE(r->tokens[i]);
  }
  free(r);
}

void free_transaction(Transaction* t)
{
  if (!t || !t->data) return;

  for (uint32_t i = 0; i < t->len; ++i)
  {
    free_resp(t->data[i]);
  }

  free(t->data);

  t->data = NULL;
  t->len = 0;
  t->cap = 0;
  t->active = 0;
}

#include <signal.h>
#include <execinfo.h>

uintptr_t get_load_address()
{
  FILE* f = fopen("/proc/self/maps", "r");
  if (!f) return 0;

  uintptr_t addr = 0;
  if (fscanf(f, "%lx", &addr) != 1)
    addr = 0;
  fclose(f);
  return addr;
}

void crash_handler(int signum)
{
  void* bt[32];
  int size = backtrace(bt, 32);
  uintptr_t base_addr = get_load_address();

  fprintf(stderr, "=== CRASH (signal %d) ===\n", signum);

  for (int i = 0; i < size; i++)
  {
    uintptr_t addr = (uintptr_t) bt[i];
    uintptr_t offset = (addr > base_addr) ? (addr - base_addr) : addr;
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "addr2line -pfi -e /proc/%d/exe 0x%lx 1>&2", getpid(), offset);
    if (i == 0) fprintf(stderr, "Debug Cmd: %s\n", cmd);
    system(cmd);
  }
  exit(1);
}

void setup_crash_handler(void)
{
  struct sigaction sa;
  sa.sa_handler = crash_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESETHAND;

  sigaction(SIGSEGV, &sa, NULL);  // segfault
  sigaction(SIGABRT, &sa, NULL);  // abort() / assert()
  sigaction(SIGFPE, &sa, NULL);  // divide by zero
  sigaction(SIGBUS, &sa, NULL);  // misaligned memory
  sigaction(SIGILL, &sa, NULL);  // illegal instruction
}

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

#ifdef DEBUG_BUILD
#  define DEBUG(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#else
#  define DEBUG(fmt, ...) do {} while (0)
#endif


void print_resp(char *title, char *buf)
{
	size_t len = strlen(buf);
	DEBUG("%s-----------[  ", title);
	for (size_t i = 0; i < len; ++i)
	{
		 if (buf[i] == '\r')
		 	DEBUG("\\r");
		 else if (buf[i] == '\n')
		 	DEBUG("\\n");
		else if(buf[i] == 0)
			DEBUG("*NULL-TERM*");
		else
			DEBUG("%c", buf[i]);
	}
	DEBUG("   ]-----------\n");

}

void get_hashed_str(const BYTE data[], char  hashed_str[SHA256_BLOCK_SIZE * 2 + 1])
{
  SHA256_CTX sha256ctx;
  sha256_init(&sha256ctx);
  sha256_update(&sha256ctx, data, strlen((char*) data));
  BYTE sha_hash_out[SHA256_BLOCK_SIZE];
  sha256_final(&sha256ctx, sha_hash_out);
  for (int i = 0; i < SHA256_BLOCK_SIZE; i++)
    sprintf(hashed_str + (i * 2), "%02x", sha_hash_out[i]);
  hashed_str[SHA256_BLOCK_SIZE * 2] = '\0';
}

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))
typedef enum 
{
	TypeString = 0x0,
	TypeStream,
	TypeList,
	TypeSortedSet,
	TypeCount,
} EntryType;

typedef struct StreamEntry
{
	uint64_t ms_time;
	int sequence_num;
	char *str;
    struct StreamEntry* next;
} StreamEntry;

typedef struct SortedSetNode
{
	double key;
	char *value;
	struct SortedSetNode** forward; // next nodes at each level
    int level;
} SortedSetNode;

#define P 0.5
#define MAX_LEVEL 6

typedef struct SkipList
{
	SortedSetNode* header;
    int level;
} SkipList;
typedef struct ZSetMember
{
	char *key;
	SortedSetNode *value;
	int rank;
	struct ZSetMember* next;
} ZSetMember;

typedef struct SortedSet
{
	ZSetMember *map[TABLE_SIZE];
	SkipList *list;
	int size;
} SortedSet;
typedef struct Entry
{
  char* key;
  char* value;
  uint64_t expiry;
  struct Entry* next;
  EntryType type;
  union
  {
    SortedSet* sorted_set;
    StreamEntry* stream; // For TypeStream entries
    char** list;
    int client_socket;
  };

  int list_cnt;
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

int read_rdb_file(char *redis_file_path, HashMap* map, char *keys[100])
{
	FILE *rdbfile = fopen(redis_file_path, "rb");
	if (rdbfile == 0)
		return 0;
	unsigned char buffer[1024 * 10];
	size_t bytes_read = fread(buffer, sizeof(unsigned char), 1024 * 10, rdbfile);
	DEBUG("bytes_read: %lu\n", bytes_read);

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
    char* key = (char*) malloc(sizeof(char) * key_len);
		strncpy(key, (char *)buffer + byte_idx, key_len);
		key[key_len] = '\0';

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

typedef struct Watched
{
  char* key;
  int socket;
  struct Watched* next;
} Watched;

Watched* watch_head;

void push_watched(Watched** head, char* key, int socket)
{
  Watched* node = (Watched*) malloc(sizeof(Watched));
  node->key = strdup(key);
  node->socket = socket;
  node->next = (*head);
  (*head) = node;
}

void removed_watched(Watched** head, char* key)
{
  Watched* temp = *head, * prev;
  if (temp != NULL && strcmp(temp->key, key) == 0)
  {
    *head = temp->next;
    free(temp->key);
    free(temp);
    return;
  }
  while (temp != NULL && strcmp(temp->key, key) != 0)
  {
    prev = temp;
    temp = temp->next;
  }
  if (temp == NULL)
    return;

  prev->next = temp->next;
  free(temp->key);
  free(temp);
}

Watched* get_watched(char* key)
{
  Watched* curr = watch_head;
  while (curr != NULL)
  {
    if (strcmp(curr->key, key) == 0)
      return curr;
    curr = curr->next;
  }
  return 0;
}

void clear_watch_list()
{
  Watched* tmp = watch_head, * prev = NULL;
  while (tmp != NULL)
  {
    Watched* next_node = tmp->next;
    if (prev == NULL)
      watch_head = next_node;
    else
      prev->next = next_node;
    free(tmp->key);
    free(tmp);
    tmp = next_node;
  }
  watch_head = NULL;
}


void *handshake(void *arg)
{
  struct sockaddr_in master_addr = {};
  master_addr.sin_family = AF_INET;
  master_addr.sin_port = htons(replication_port);
  master_addr.sin_addr.s_addr = INADDR_ANY;
   
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
	DEBUG("rdb_file_bytes: %lu\n", rdb_file_bytes);

	char *rdb_buffer = strstr(rdb_preamble, "\n") + 1;

	size_t end_rdb_buffer = (rdb_buffer+rdb_file_bytes) - buf;
	
	DEBUG("end_rdb_buffer: %lu\n", end_rdb_buffer);
	DEBUG("bytes_read: %lu\n", bytes_read);

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

char *keys[100];
int replica_socks[10] = {0};
int replica_socks_cnt = 0;
int did_propogate_to_replica = 0;

#define BUF_SIZE 1024

void handle_get_command(char output_buf[BUF_SIZE], Resp *cmd)
{
	Entry *val = hashmap_get_entry(map, PSTR(cmd->tokens[1]));

	if (val && val->expiry > get_curr_time())
	{
		snprintf(output_buf, BUF_SIZE, "$%lu\r\n%s\r\n", strlen(val->value), val->value);
	}
	else
		snprintf(output_buf, BUF_SIZE, "$-1\r\n");
}

void handle_set_command(char output_buf[BUF_SIZE], Resp *cmd)
{
	uint64_t expiry_time = UINT64_MAX;
	

	if (cmd->len > 3 && (c_str_eq(cmd->tokens[3], "px") || c_str_eq(cmd->tokens[3], "PX")))
	{
		uint64_t curr_time = get_curr_time();
		expiry_time = curr_time + atoll(PSTR(cmd->tokens[4]));
	}

	hashmap_put(map, PSTR(cmd->tokens[1]), PSTR(cmd->tokens[2]), expiry_time, TypeString);
	snprintf(output_buf, BUF_SIZE, "+OK\r\n");

	did_propogate_to_replica = replica_socks_cnt;

  if (replica_socks_cnt)
  {
    char raw_resp[512];
    size_t raw_resp_size = snprintf(raw_resp, sizeof(raw_resp), "*%u\r\n", cmd->len);

    for (int i = 0; i < cmd->len; i++)
      raw_resp_size += snprintf(raw_resp + raw_resp_size, sizeof(raw_resp), "$%zu\r\n%s\r\n", LSTR(cmd->tokens[i]), PSTR(cmd->tokens[i]));

    for (int i = 0; i < replica_socks_cnt; ++i)
    {
      write(replica_socks[i], raw_resp, raw_resp_size);
    }
  }
}

void handle_incr_command(char output_buf[BUF_SIZE], Resp *cmd)
{	
	Entry *val = hashmap_get_entry(map, PSTR(cmd->tokens[1]));

	if (val)
	{
		int num = INT_MIN;
		sscanf(val->value, "%d", &num);
		if (num == INT_MIN)
		{
			snprintf(output_buf, BUF_SIZE, "-ERR value is not an integer or out of range\r\n");
		} else
		{
			num++;
			free(val->value);
			char num_str[10];
			snprintf(num_str, sizeof(num_str), "%d", num);
			val->value = strdup(num_str);
			snprintf(output_buf, BUF_SIZE, ":%d\r\n", num);	
		}
	} else
	{
		hashmap_put(map, PSTR(cmd->tokens[1]), "1", UINT64_MAX, TypeString);
		snprintf(output_buf, BUF_SIZE, ":1\r\n");
	}
}

void handle_exec_command(char output_buf[BUF_SIZE], Transaction *t, int client_socket)
{
	if (!t->active)
	{
		snprintf(output_buf, BUF_SIZE, "-ERR EXEC without MULTI\r\n");
		return;
	}
	if (t->len == 0)
	{
		snprintf(output_buf, BUF_SIZE, "*0\r\n");
		return;
	}

  int abort_txn = 0;
  Watched* tmp = watch_head, * prev = NULL;
  while (tmp != NULL)
  {
    Watched* next_node = tmp->next;
    if (tmp->socket != client_socket)
    {
      abort_txn = 1;
      break;
    }
      
    prev = tmp;
    tmp = next_node;
  }

  clear_watch_list();

  if (abort_txn)
  {
    strcpy(output_buf, "*-1\r\n");
    return;
  }

	char exec_output_buf[BUF_SIZE];
	int buf_offset = snprintf(exec_output_buf, BUF_SIZE, "*%d\r\n", t->len);
	for (int trans_idx = 0; trans_idx < t->len; ++trans_idx)
	{
    Resp* cmd = t->data[trans_idx];
    String command = cmd->tokens[0];

		if (c_str_eq(command, "SET"))
			handle_set_command(output_buf, cmd);
		else if (c_str_eq(command, "INCR"))
			handle_incr_command(output_buf, cmd);
		else if (c_str_eq(command, "GET"))
			handle_get_command(output_buf, cmd);
		
		buf_offset += snprintf(exec_output_buf+buf_offset, BUF_SIZE, "%s", output_buf);

	}
	strcpy(output_buf, exec_output_buf);
  next_cmd:;
}

void handle_xread_command(char output_buf[BUF_SIZE], Resp *cmd, int stream_count)
{
	char *stream_keys[100];
	char *IDs[100];
	int token_idx = 2;
	int blocking = 0;
	useconds_t block_ms;
	if (c_str_eq(cmd->tokens[1], "block"))
	{
		blocking = 1;
		stream_count -= 1;
		token_idx = 4;

		sscanf(PSTR(cmd->tokens[2]), "%u", &block_ms);
		block_ms *= 1000;
		usleep(block_ms);
	}

	for (int i = 0; i < stream_count; ++i)
		stream_keys[i] = PSTR(cmd->tokens[token_idx++]);

	for (int i = 0; i < stream_count; ++i)
		IDs[i] = PSTR(cmd->tokens[token_idx++]);

	int only_new_entries = 0;
  if (cmd->len > 5 && c_str_eq(cmd->tokens[5], "$"))
		only_new_entries = 1;

	int things_added = 0;
	uint64_t entry_time;
	int entry_seq;
	do
	{
		int buf_offet = 0;
		buf_offet += snprintf(output_buf+buf_offet, BUF_SIZE, "*%d\r\n", stream_count);
		for (int i = 0; i < stream_count; ++i)
		{
			char *stream_key = stream_keys[i];
			Entry *entry = hashmap_get_entry(map, stream_key);

			buf_offet += snprintf(output_buf+buf_offet, BUF_SIZE, "*2\r\n$%lu\r\n%s\r\n", strlen(stream_key), stream_key);

			sscanf(IDs[i], "%lu-%d", &entry_time, &entry_seq);
			if (only_new_entries == 1)
			{
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
					buf_offet += snprintf(output_buf+buf_offet, BUF_SIZE, "*1\r\n%s", stream_entry->str);
					if (blocking && block_ms == 0)
						return;
				}
				if (only_new_entries && stream_entry->next == 0)
				{
					entry_seq = stream_entry->sequence_num;
					entry_time = stream_entry->ms_time;
					only_new_entries = 0;
				}
				stream_entry = stream_entry->next;
				if (block_ms == 0)
					usleep(1);
			}
		}
	} while (blocking && block_ms == 0);

	if (blocking && things_added == 0)
		snprintf(output_buf, BUF_SIZE, "*-1\r\n");
}

Entry *create_list(char *listname)
{
  Entry* list = (Entry*) calloc(1, sizeof(Entry));
	list->key = strdup(listname);
  list->list = (char**) calloc(100, sizeof(char*));
	list->list += 50; // pointer to the middle (So LPUSH is easy)
	list->list_cnt = 0;
	list->expiry = UINT64_MAX;
	list->type = TypeList;
	
	unsigned int index = hash(listname);
	map->table[index] = list;
	return list;
}

void zset_map_put(SortedSet *set, const char *key, SortedSetNode *value, int rank)
{
	unsigned int index = hash(key);
	ZSetMember *current = set->map[index];
	while (current != NULL)
	{
		if (strcmp(current->key, key) == 0)
		{
			current->value = value;
			current->rank = rank;
			return;
		}
		current = current->next;
	}

	ZSetMember *newEntry = (ZSetMember *)malloc(sizeof(ZSetMember));
	if (newEntry == NULL)
		return;
	newEntry->key = strdup(key);
	newEntry->value = value;
	newEntry->rank = rank;
	newEntry->next = set->map[index];
	set->map[index] = newEntry;
}
ZSetMember* zset_get(SortedSet* set, const char* key)
{
    unsigned int index = hash(key);
    ZSetMember* current = set->map[index];
    
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

SortedSetNode *skiplist_create_node(double key, char *value, int level)
{
	SortedSetNode *node = (SortedSetNode *)malloc(sizeof(SortedSetNode));
	node->key = key;
	node->value = strdup(value);
	node->level = level;
	node->forward = (SortedSetNode **)malloc(sizeof(SortedSetNode *) * (level + 1));

	for (int i = 0; i <= level; i++)
		node->forward[i] = NULL;
	return node;
}

SkipList *create_skip_list()
{
	SkipList* list = (SkipList*)malloc(sizeof(SkipList));
    
    list->header = skiplist_create_node(-1, (char*) "", MAX_LEVEL);
    list->level = 0;
    return list;
}
int random_level()
{
	int level = 0;
	while (((float)rand() / (float)RAND_MAX) < P && level < MAX_LEVEL)
		level++;
	return level;
}
void skiplist_insert(SkipList *list, double key, char *value)
{
	SortedSetNode *current = list->header;
	SortedSetNode *update[MAX_LEVEL + 1];

	for (int i = list->level; i >= 0; i--)
	{
		while (current->forward[i] != NULL &&
			   (current->forward[i]->key < key ||
				(current->forward[i]->key == key && strcmp(current->forward[i]->value, value) < 0)))
		{
			current = current->forward[i];
		}
		update[i] = current;
	}
	current = current->forward[0];
	int newLevel = random_level();

	if (newLevel > list->level)
	{
		for (int i = list->level + 1; i <= newLevel; i++)
		{
			update[i] = list->header;
		}
		list->level = newLevel;
	}

	SortedSetNode *newNode = skiplist_create_node(key, value, newLevel);


	for (int i = 0; i <= newLevel; i++)
	{
		newNode->forward[i] = update[i]->forward[i];
		update[i]->forward[i] = newNode;
	}
}

void skiplist_remove(SkipList *list, double key, char *value)
{
	SortedSetNode *current = list->header;
	SortedSetNode *update[MAX_LEVEL + 1];

	for (int i = list->level; i >= 0; i--)
	{
		while (current->forward[i] != NULL &&
			   (current->forward[i]->key < key ||
				(current->forward[i]->key == key && strcmp(current->forward[i]->value, value) < 0)))
		{
			current = current->forward[i];
		}
		update[i] = current;
	}
	current = current->forward[0];

	while (current != NULL && current->key == key)
	{
		if (strcmp(current->value, value) == 0)
		{
			for (int i = 0; i <= list->level; i++)
			{
				if (update[i]->forward[i] != current)
					break;

				update[i]->forward[i] = current->forward[i];
			}

			free(current->value);
			free(current->forward);
			free(current);

			while (list->level > 0 && list->header->forward[list->level] == NULL)
				list->level--;

			return;
		}
		current = current->forward[0];
	}
}

void skiplist_traverse(SortedSet *set)
{
	SkipList *list = set->list;
	SortedSetNode *current = list->header->forward[0];
	int rank = 0;
	while (current != NULL)
	{
		// DEBUG("[%f:\"%s\"] ",  current->key, current->value);
		zset_map_put(set, current->value, current, rank++);
		current = current->forward[0];
	}
	// DEBUG("\n");
	set->size = rank;
}

int insert_into_sorted_set(char *zset_key, char *zset_member, double key)
{
	Entry *e = hashmap_get_entry(map, zset_key);
	if (e == NULL)
	{
		hashmap_put(map, zset_key, "", UINT64_MAX, TypeSortedSet);
		e = hashmap_get_entry(map, zset_key);
    e->sorted_set = (SortedSet*) calloc(1, sizeof(SortedSet));
		e->sorted_set->list = create_skip_list();
		skiplist_insert(e->sorted_set->list, key, zset_member);
		e->sorted_set->size = 1;
		for (int i = 0; i < TABLE_SIZE; i++)
		{
			e->sorted_set->map[i] = NULL;
		}
		zset_map_put(e->sorted_set, zset_member, e->sorted_set->list->header->forward[0], 1);
		return 1;
	}
    ZSetMember* member = zset_get(e->sorted_set, zset_member);
	int res = 1;
	if (member)
	{
		res = 0;
		skiplist_remove(e->sorted_set->list, member->value->key, member->key);
	}
	skiplist_insert(e->sorted_set->list, key, zset_member);
	skiplist_traverse(e->sorted_set);
	return res;
}
pthread_mutex_t lpop_mutex;

#define MIN_LATITUDE -85.05112878L
#define MAX_LATITUDE 85.05112878L
#define MIN_LONGITUDE -180.0L
#define MAX_LONGITUDE 180.0L

#define LATITUDE_RANGE (MAX_LATITUDE - MIN_LATITUDE)
#define LONGITUDE_RANGE (MAX_LONGITUDE - MIN_LONGITUDE)

uint64_t spread_int32_to_int64(uint32_t v)
{
	uint64_t result = v;
	result = (result | (result << 16)) & 0x0000FFFF0000FFFFULL;
	result = (result | (result << 8))  & 0x00FF00FF00FF00FFULL;
	result = (result | (result << 4))  & 0x0F0F0F0F0F0F0F0FULL;
	result = (result | (result << 2))  & 0x3333333333333333ULL;
	result = (result | (result << 1))  & 0x5555555555555555ULL;
	return result;
}

uint64_t coord_encode(double latitude, double longitude)
{
	// Normalize to the range 0-2^26
	double normalized_latitude = pow(2, 26) * (latitude - MIN_LATITUDE) / LATITUDE_RANGE;
	double normalized_longitude = pow(2, 26) * (longitude - MIN_LONGITUDE) / LONGITUDE_RANGE;

	// Truncate to integers
	uint32_t lat_int = (uint32_t)normalized_latitude;
	uint32_t lon_int = (uint32_t)normalized_longitude;

	uint64_t x_spread = spread_int32_to_int64(lat_int);
	uint64_t y_spread = spread_int32_to_int64(lon_int);
	uint64_t y_shifted = y_spread << 1;
	return x_spread | y_shifted;
}
typedef struct
{
	double latitude;
	double longitude;
} coordinates_t;

uint32_t compact_int64_to_int32(uint64_t v)
{
	v = v & 0x5555555555555555ULL;
	v = (v | (v >> 1))  & 0x3333333333333333ULL;
	v = (v | (v >> 2))  & 0x0F0F0F0F0F0F0F0FULL;
	v = (v | (v >> 4))  & 0x00FF00FF00FF00FFULL;
	v = (v | (v >> 8))  & 0x0000FFFF0000FFFFULL;
	v = (v | (v >> 16)) & 0x00000000FFFFFFFFULL;
	return (uint32_t)v;
}

coordinates_t convert_grid_numbers_to_coordinates(uint32_t grid_latitude_number, uint32_t grid_longitude_number)
{
	coordinates_t result;

	// Calculate the grid boundaries
	double grid_latitude_min = MIN_LATITUDE + LATITUDE_RANGE * (grid_latitude_number / pow(2, 26));
	double grid_latitude_max = MIN_LATITUDE + LATITUDE_RANGE * ((grid_latitude_number + 1) / pow(2, 26));
	double grid_longitude_min = MIN_LONGITUDE + LONGITUDE_RANGE * (grid_longitude_number / pow(2, 26));
	double grid_longitude_max = MIN_LONGITUDE + LONGITUDE_RANGE * ((grid_longitude_number + 1) / pow(2, 26));

	// Calculate the center point of the grid cell
	result.latitude = (grid_latitude_min + grid_latitude_max) / 2;
	result.longitude = (grid_longitude_min + grid_longitude_max) / 2;

	return result;
}

coordinates_t decode_coord(uint64_t geo_code)
{
	// Align bits of both latitude and longitude to take even-numbered position
	uint64_t y = geo_code >> 1;
	uint64_t x = geo_code;

	// Compact bits back to 32-bit ints
	uint32_t grid_latitude_number = compact_int64_to_int32(x);
	uint32_t grid_longitude_number = compact_int64_to_int32(y);

	return convert_grid_numbers_to_coordinates(grid_latitude_number, grid_longitude_number);
}
const double EARTH_RADIUS_IN_METERS = 6372797.560856;
static inline double deg_to_rad(double deg)
{
	return deg * M_PI / 180.0;
	
}
static inline double rad_to_deg(double rad)
{
	return rad / ( 180.0 / M_PI);
}

double get_distance(coordinates_t coord_a, coordinates_t coord_b)
{
	double lat1_rad = deg_to_rad(coord_a.latitude);
	double lon1_rad = deg_to_rad(coord_a.longitude);
	double lat2_rad = deg_to_rad(coord_b.latitude);
	double lon2_rad = deg_to_rad(coord_b.longitude);

	double delta_lat = lat2_rad - lat1_rad;
	double delta_lon = lon2_rad - lon1_rad;

	double a = sin(delta_lat / 2.0) * sin(delta_lat / 2.0) +
			   cos(lat1_rad) * cos(lat2_rad) *
				   sin(delta_lon / 2.0) * sin(delta_lon / 2.0);

	double c = 2.0 * atan2(sqrt(a), sqrt(1.0 - a));
	return EARTH_RADIUS_IN_METERS * c;
}

int append_idx = 1;
int append_only = 0;
char full_append_path[PATH_MAX];

void *handle_client(void *arg)
{
  int authenticated = 0;
  int subscribe_mode = 0;
  int client_sock = *(int*) arg;
  free(arg);
  DEBUG("Client connected - port: %d - client_sock: %d\n", port, client_sock);

  char req_buf[BUF_SIZE];
  char output_buf[BUF_SIZE * 2];

  Transaction transaction = init_transaction();
  
  Resp cmd = { 0 };
  ssize_t bytes_read = 0;
  ssize_t bytes_processed = 0; 

  while (bytes_read > bytes_processed || (bytes_read = bytes_processed = 0, bytes_read += read(client_sock, req_buf, BUF_SIZE)))
  {
    req_buf[bytes_read] = 0;
    int offset;
    sscanf(req_buf+bytes_processed, "*%d\r\n%n", &cmd.len, &offset);
    bytes_processed += offset;
    for (int i = 0; i < cmd.len; ++i)
    {
      int char_cnt;
      sscanf(req_buf+bytes_processed, "$%d\r\n%n", &char_cnt, &offset);
      bytes_processed += offset;
      cmd.tokens[i] = _str_cpy((const char*) req_buf + bytes_processed, char_cnt);
      bytes_processed += char_cnt + 2;
    }

		String command = cmd.tokens[0];

    if (append_only &&
      (!c_str_eq(command, "GET")) &&
      (!c_str_eq(command, "ECHO")))
    {
      FILE* fp = fopen(full_append_path, "a");
      fprintf(fp, "%s", req_buf);
      fclose(fp);
    }


    if (subscribe_mode &&
      !(c_str_eq(command, "SUBSCRIBE") ||
      c_str_eq(command, "UNSUBSCRIBE") ||
      c_str_eq(command, "PSUBSCRIBE") ||
      c_str_eq(command, "PUNSUBSCRIBE") ||
      c_str_eq(command, "QUIT") ||
      c_str_eq(command, "RESET")))
    {
      if (c_str_eq(command, "PING"))
        snprintf(output_buf, sizeof(output_buf), "*2\r\n$4\r\npong\r\n$0\r\n\r\n");
      else
        snprintf(output_buf, sizeof(output_buf),
          "-ERR Can't execute '%s': only (P|S)SUBSCRIBE / (P|S)UNSUBSCRIBE / PING / QUIT / RESET are allowed in this context\r\n",
          PSTR(command));
      write(client_sock, output_buf, strlen(output_buf));
      continue;
    }

    if (transaction.active &&
      ((c_str_eq(command, "SET")) ||
      (c_str_eq(command, "GET")) ||
      (c_str_eq(command, "INCR"))))
    { 
      push_transaction(&transaction, &cmd);
      write(client_sock, "+QUEUED\r\n", strlen("+QUEUED\r\n"));
    	continue;
    }


    if (c_str_eq(command, "COMMAND"))
    {
      write(client_sock, "+OK\r\n", strlen("+OK\r\n"));
      continue;
    }

		if (c_str_eq(command, "PING"))
		{
			snprintf(output_buf, sizeof(output_buf), "+PONG\r\n");
		}
    else if (c_str_eq(command, "ECHO"))
		{
			snprintf(output_buf, sizeof(output_buf), "$%lu\r\n%.*s\r\n", LSTR(cmd.tokens[1]), (int)LSTR(cmd.tokens[1]), PSTR(cmd.tokens[1]));
		}
		else if (c_str_eq(command, "SET"))
		{
			handle_set_command(output_buf, &cmd);
      Watched* tmp = get_watched(PSTR(cmd.tokens[1]));
      if (tmp)
        tmp->socket = client_sock;
		}
		else if (c_str_eq(command, "GET"))
		{
			handle_get_command(output_buf, &cmd);
		}
		else if (c_str_eq(command, "INCR"))
		{
			handle_incr_command(output_buf, &cmd);
		}

		else if (c_str_eq(command, "CONFIG"))
		{
			if (c_str_eq(cmd.tokens[1], "GET"))
			{  
        char *get_opt = shget(config, PSTR(cmd.tokens[2]));
        snprintf(output_buf, sizeof(output_buf), "*2\r\n$%lu\r\n%s\r\n$%lu\r\n%s\r\n",
          LSTR(cmd.tokens[2]), PSTR(cmd.tokens[2]),
          strlen(get_opt), get_opt);
			}
		}
		else if (c_str_eq(command, "KEYS"))
		{
			int offset = snprintf(output_buf, sizeof(output_buf), "*%d\r\n", db_map_size);
			for (int i = 0; i < db_map_size && offset < sizeof(output_buf); ++i)
			{
				offset += snprintf(output_buf + offset, sizeof(output_buf) - offset,
								   "$%lu\r\n%s\r\n", strlen(keys[i]), keys[i]);
			}
		}
		else if (c_str_eq(command, "INFO"))
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
		else if (c_str_eq(command, "REPLCONF"))
		{
			snprintf(output_buf, sizeof(output_buf), "+OK\r\n");
		}
		else if (c_str_eq(command, "PSYNC"))
		{
			snprintf(output_buf, sizeof(output_buf), "+FULLRESYNC 8371b4fb1155b71f4a04d3e1bc3e18c4a990aeeb 0\r\n");
			write(client_sock, output_buf, strlen(output_buf));
			write(client_sock,
				  "$88\r\n\x52\x45\x44\x49\x53\x30\x30\x31\x31\xfa\x09\x72\x65\x64\x69\x73\x2d\x76\x65\x72\x05\x37\x2e\x32\x2e\x30\xfa\x0a\x72\x65\x64\x69\x73\x2d\x62\x69\x74\x73\xc0\x40\xfa\x05\x63\x74\x69\x6d\x65\xc2\x6d\x08\xbc\x65\xfa\x08\x75\x73\x65\x64\x2d\x6d\x65\x6d\xc2\xb0\xc4\x10\x00\xfa\x08\x61\x6f\x66\x2d\x62\x61\x73\x65\xc0\x00\xff\xf0\x6e\x3b\xfe\xc0\xff\x5a\xa2",
				  88 + 5);
			replica_socks[replica_socks_cnt++] = client_sock;
			DEBUG("replica_sock: %d\n", client_sock);
			return 0;
		}
		else if (c_str_eq(command, "WAIT"))
		{ 
			if (did_propogate_to_replica == 0)
			{ 
				snprintf(output_buf, sizeof(output_buf), ":%d\r\n", replica_socks_cnt);
				write(client_sock, output_buf, strlen(output_buf));
				continue;
			}

			int timeout_ms = atoi(PSTR(cmd.tokens[2]));
			int min_replica_processed_cnt = atoi(PSTR(cmd.tokens[1]));

			DEBUG("replica_socks_cnt: %d\n", replica_socks_cnt);
			DEBUG("min_replica_processed_cnt: %d\n", min_replica_processed_cnt);

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
					DEBUG("Total timeout reached, stopping polling.\n");
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
		else if (c_str_eq(command, "TYPE"))
		{
			Entry *val = hashmap_get_entry(map, PSTR(cmd.tokens[1]));
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
		else if (c_str_eq(command, "XADD"))
		{
      char* entry_key = PSTR(cmd.tokens[1]);
			char* ID = PSTR(cmd.tokens[2]);
			uint64_t ms_time;
			int sequence_num;
			char *stream_key = PSTR(cmd.tokens[3]);
			char *stream_val = PSTR(cmd.tokens[4]);

			if (strncmp(ID, "*", 2) == 0)
			{
				sequence_num = 0;
				ms_time = get_curr_time();
			}
			else
			{
				sscanf(ID, "%lu-%d", &ms_time, &sequence_num);
				char sequence_char;
				sscanf(ID, "%*u-%c", &sequence_char);
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
								 "%lu-%d %s:%s\n", ms_time, sequence_num, stream_key, stream_val);
				char new_id[256];
				snprintf(new_id, sizeof(new_id),"%lu-%d", ms_time, sequence_num);
				
				snprintf(output_buf, sizeof(output_buf), "$%lu\r\n%s\r\n", strlen(new_id), new_id);	
				hashmap_put(map, entry_key, stream_str, UINT64_MAX, TypeStream);
				
				int stream_resp_offset = 0;
				stream_resp_offset += snprintf(stream_resp+stream_resp_offset, sizeof(stream_resp), "*2\r\n$%lu\r\n%s\r\n*%d\r\n", strlen(new_id), new_id, cmd.len - 3);
				for (int i = 3; i < cmd.len; ++i)
					stream_resp_offset += snprintf(stream_resp+stream_resp_offset, sizeof(stream_resp), "$%lu\r\n%s\r\n", LSTR(cmd.tokens[i]), PSTR(cmd.tokens[i]));

				val = hashmap_get_entry(map, entry_key);
        val->stream = (StreamEntry*) calloc(1, sizeof(StreamEntry));
				val->stream->ms_time = ms_time;
				val->stream->sequence_num = sequence_num;
				val->stream->str = strdup(stream_resp);
				val->stream->next = 0;

			} else
			{
				uint64_t last_ms_time;
				int last_sequence_num;
				sscanf(val->value, "%lu-%d", &last_ms_time, &last_sequence_num);

				if (sequence_num == -1)
				{
					if (ms_time == last_ms_time)
						sequence_num = last_sequence_num + 1;
					else
						sequence_num = 0;
				}
				
				snprintf(stream_str, sizeof(stream_str),
					"%lu-%d %s:%s\n", ms_time, sequence_num, stream_key, stream_val);

				if (ms_time > last_ms_time || (ms_time == last_ms_time && sequence_num > last_sequence_num))
				{
					char new_id[256];
					snprintf(new_id, sizeof(new_id),"%lu-%d", ms_time, sequence_num);

					snprintf(output_buf, sizeof(output_buf), "$%lu\r\n%s\r\n", strlen(new_id), new_id);
					if (val->value)
						free(val->value);
					val->value = strdup(stream_str);

					StreamEntry *stream_entry = val->stream;
					while(stream_entry->next)
					{
						stream_entry = stream_entry->next;
					}

					int stream_resp_offset = 0;
					stream_resp_offset += snprintf(stream_resp+stream_resp_offset, sizeof(stream_resp), "*2\r\n$%lu\r\n%s\r\n*%d\r\n", strlen(new_id), new_id, cmd.len - 3);
					for (int i = 3; i < cmd.len; ++i)
						stream_resp_offset += snprintf(stream_resp+stream_resp_offset, sizeof(stream_resp), "$%lu\r\n%s\r\n", LSTR(cmd.tokens[i]), PSTR(cmd.tokens[i]));

          stream_entry->next = (StreamEntry*) calloc(1, sizeof(StreamEntry));
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
		else if (c_str_eq(command, "XRANGE"))
		{
			
			char *stream_key = PSTR(cmd.tokens[1]);
			uint64_t start_time = 0, end_time;
      int start_seq = 0, end_seq = INT_MAX;
      if (!c_str_eq(cmd.tokens[2], "-"))
        sscanf(PSTR(cmd.tokens[2]), "%lu-%d", &start_time, &start_seq);
			
			sscanf(PSTR(cmd.tokens[3]), "%lu-%d", &end_time, &end_seq);
			
			char temp_buff[1024];
			int offset = 0;

			Entry *entry = hashmap_get_entry(map, stream_key);
			StreamEntry *stream_entry = entry->stream;
			int matching_entries = 0;
			while (stream_entry)
			{
				if ((stream_entry->ms_time >= start_time && stream_entry->sequence_num >= start_seq) &&
					(stream_entry->ms_time <= end_time && stream_entry->sequence_num <= end_seq))
				{
					matching_entries++;
					offset += snprintf(temp_buff+offset, sizeof(temp_buff), "%s", stream_entry->str);
				}
				stream_entry = stream_entry->next;
			}
			snprintf(output_buf, sizeof(output_buf), "*%d\r\n%s", matching_entries, temp_buff);
		}
		else if (c_str_eq(command, "XREAD"))
		{
			int stream_count = (cmd.len - 2) / 2;
			handle_xread_command(output_buf, &cmd, stream_count);
		}

		else if (c_str_eq(command, "MULTI"))
		{
			transaction.active = 1;
			snprintf(output_buf, sizeof(output_buf), "+OK\r\n");
		}

		else if (c_str_eq(command, "EXEC"))
		{
      handle_exec_command(output_buf, &transaction, client_sock);
      free_transaction(&transaction);
		}
		else if (c_str_eq(command, "DISCARD"))
		{
			snprintf(output_buf, sizeof(output_buf), "+OK\r\n");
			if (!transaction.active)
				snprintf(output_buf, sizeof(output_buf), "-ERR DISCARD without MULTI\r\n");
			free_transaction(&transaction);
      clear_watch_list();
		}
		else if (c_str_eq(command, "RPUSH"))
		{
			char *listname = PSTR(cmd.tokens[1]);
			Entry *list = hashmap_get_entry(map, listname);
			if (list == NULL)
			{
				list = create_list(listname);
			}

			for (int i = 2; i < cmd.len; ++i)
				list->list[list->list_cnt++] = strdup(PSTR(cmd.tokens[i]));	 

			snprintf(output_buf, sizeof(output_buf), ":%d\r\n", list->list_cnt);
		}
		else if (c_str_eq(command, "LPUSH"))
		{
			char *listname = PSTR(cmd.tokens[1]);
			Entry *list = hashmap_get_entry(map, listname);
			if (list == NULL)
			{
				list = create_list(listname);
			}
			list->list -= (cmd.len - 2);
			for (int i = cmd.len - 1, j = 0; i >= 2; --i)
			{
				list->list[j++] = strdup(PSTR(cmd.tokens[i]));
				list->list_cnt++;
			}
			snprintf(output_buf, sizeof(output_buf), ":%d\r\n", list->list_cnt);
		}
		else if (c_str_eq(command, "LLEN"))
		{
			char *listname = PSTR(cmd.tokens[1]);
			Entry *list = hashmap_get_entry(map, listname);
			int llen = 0;
			if (list)
				llen = list->list_cnt;
			snprintf(output_buf, sizeof(output_buf), ":%d\r\n", llen);
		}
		else if (c_str_eq(command, "LPOP"))
		{
			char *listname = PSTR(cmd.tokens[1]);
			Entry *list = hashmap_get_entry(map, listname);

			int count = 1;
			if (cmd.len == 3)
				count = atoi(PSTR(cmd.tokens[2]));
			if (list == NULL)
			{
				write(client_sock, "*0\r\n", strlen("*0\r\n"));
				close(client_sock);
				return NULL;
			}

			if (count == 1)
				snprintf(output_buf, sizeof(output_buf), "$%lu\r\n%s\r\n", strlen(list->list[0]), list->list[0]);
			else
			{
				int offset = snprintf(output_buf, sizeof(output_buf), "*%d\r\n", count);
				for (int i = 0; i < count; ++i)
					offset += snprintf(output_buf + offset, sizeof(output_buf), "$%lu\r\n%s\r\n", strlen(list->list[i]), list->list[i]);
			}
			list->list += count;
			list->list_cnt -= count;
		}
		else if (c_str_eq(command, "BLPOP"))
		{
			pthread_mutex_lock(&lpop_mutex);
			char *listname = PSTR(cmd.tokens[1]);
			float timeout_sec = 0;
			if (cmd.len == 3)
				timeout_sec = atof(PSTR(cmd.tokens[2]));
			
			Entry *list = hashmap_get_entry(map, listname);
			if (list == NULL)
				list = create_list(listname);

			useconds_t timeout_mic_sec = (useconds_t)(timeout_sec*1000000);
			if (timeout_mic_sec>0)
			{
				usleep(timeout_mic_sec);
			}
			else
			{
				while (list->list_cnt == 0)
					usleep(100);
			}
			if (list->list_cnt > 0)
			{
				snprintf(output_buf, sizeof(output_buf), "*2\r\n$%lu\r\n%s\r\n$%lu\r\n%s\r\n", strlen(listname), listname, strlen(list->list[0]), list->list[0]);
				list->list += 1;
				list->list_cnt -= 1;
			} else
			{
				snprintf(output_buf, sizeof(output_buf), "*-1\r\n");
			}
			pthread_mutex_unlock(&lpop_mutex);
		}
		else if (c_str_eq(command, "LRANGE"))
		{
			char *listname = PSTR(cmd.tokens[1]);
			int beg = atoi(PSTR(cmd.tokens[2]));
			int end = atoi(PSTR(cmd.tokens[3]));

			Entry *list = hashmap_get_entry(map, listname);
			if (list == NULL)
			{
				write(client_sock, "*0\r\n", strlen("*0\r\n"));
				close(client_sock);
				return NULL;
			}

			if (beg < 0)
				beg = list->list_cnt+beg;
			if (end < 0)
				end = list->list_cnt+end;

			if (beg < 0)
				beg = 0;
			if (end < 0)
				end = 0;

			char temp[1024];
			temp[0] = 0;
			int offset = 0;
			int count = 0;
			for (int i = beg; i <= end && i < list->list_cnt; ++i)
			{
				if (list->list[i])
				{
					count++;
					offset += snprintf(temp + offset, sizeof(temp), "$%lu\r\n%s\r\n", strlen(list->list[i]), list->list[i]);
				}
			}
			snprintf(output_buf, sizeof(output_buf), "*%d\r\n%s", count, temp);
		}
		
		else if (c_str_eq(command, "SUBSCRIBE"))
		{
			char sub[256];
			snprintf(sub, sizeof(sub), "%d%s", client_sock, PSTR(cmd.tokens[0]));
			subscribe_mode = 1;
			Entry *subscribe = hashmap_get_entry(map, sub);
			if (subscribe == NULL)
				subscribe = create_list(sub);

			Entry *channel = hashmap_get_entry(map, PSTR(cmd.tokens[1]));
			if (channel == NULL)
				channel = create_list(PSTR(cmd.tokens[1]));
			channel->list[channel->list_cnt++] = strdup(sub);

			subscribe->list[subscribe->list_cnt++] = strdup(PSTR(cmd.tokens[1]));
			snprintf(output_buf, sizeof(output_buf), "*3\r\n$%lu\r\n%s\r\n$%lu\r\n%s\r\n:%d\r\n", strlen("subscribe"), "subscribe", LSTR(cmd.tokens[1]), PSTR(cmd.tokens[1]), subscribe->list_cnt);
		}
		else if (c_str_eq(command, "UNSUBSCRIBE"))
		{
			char sub[256];
			snprintf(sub, sizeof(sub), "%dSUBSCRIBE", client_sock);

			Entry *channel = hashmap_get_entry(map, PSTR(cmd.tokens[1]));
			for (int i = 0; i < channel->list_cnt; ++i)
			{
				if (strcmp(channel->list[i], sub) == 0)
				{
					free(channel->list[i]);
					channel->list[i] = channel->list[--channel->list_cnt]; // swaping last itme to empty spot
				}
			}

			Entry *subscribe = hashmap_get_entry(map, sub);
			subscribe->list_cnt--;
			snprintf(output_buf, sizeof(output_buf), "*3\r\n$%lu\r\n%s\r\n$%lu\r\n%s\r\n:%d\r\n", strlen("unsubscribe"), "unsubscribe", LSTR(cmd.tokens[1]), PSTR(cmd.tokens[1]), subscribe->list_cnt);
		}
		else if (c_str_eq(command, "PUBLISH"))
		{
			char *channel = PSTR(cmd.tokens[1]);
			Entry *subscribe = hashmap_get_entry(map, channel);
			int count = 0;
			if (subscribe)
				count = subscribe->list_cnt;

			for (int i = 0; i < count; ++i)
			{
				int socket = atoi(subscribe->list[i]);
				char temp[256];
				snprintf(temp, sizeof(temp), "*3\r\n$7\r\nmessage\r\n$%lu\r\n%s\r\n$%lu\r\n%s\r\n", strlen(channel), channel, LSTR(cmd.tokens[2]), PSTR(cmd.tokens[2]));
				write(socket, temp, strlen(temp));
			}
			snprintf(output_buf, sizeof(output_buf), ":%d\r\n", count);
		}
		else if (c_str_eq(command, "ZADD"))
		{
			char *zset_key = PSTR(cmd.tokens[1]);
			double value = atof(PSTR(cmd.tokens[2]));
			char *zset_member = PSTR(cmd.tokens[3]);
			int res = insert_into_sorted_set(zset_key, zset_member, value);
			snprintf(output_buf, sizeof(output_buf), ":%d\r\n", res);
		}
		else if (c_str_eq(command, "ZRANK"))
		{
			char *zset_key = PSTR(cmd.tokens[1]);
			char *zset_member = PSTR(cmd.tokens[2]);
			Entry *e = hashmap_get_entry(map, zset_key);
			
			snprintf(output_buf, sizeof(output_buf), "$-1\r\n");

			if (e)
			{
				ZSetMember *member = zset_get(e->sorted_set, zset_member);
				if (member)
					snprintf(output_buf, sizeof(output_buf), ":%d\r\n", member->rank);
			}
		}

		else if (c_str_eq(command, "ZRANGE"))
		{
			char *zset_key = PSTR(cmd.tokens[1]);
			int beg = atoi(PSTR(cmd.tokens[2]));
			int end = atoi(PSTR(cmd.tokens[3]));
			Entry *e = hashmap_get_entry(map, zset_key);

			snprintf(output_buf, sizeof(output_buf), "*0\r\n");
			if (e)
			{
				int total = e->sorted_set->size;
				if (beg < 0)
					beg = total + beg;
				if (end < 0)
					end = total + end;

				end = MIN(total, end);
				int res_count = MIN(end+1-beg, total);
				int offset = snprintf(output_buf, sizeof(output_buf), "*%d\r\n", res_count);

				SkipList *list = e->sorted_set->list;
				SortedSetNode *current = list->header->forward[0];
				int idx = 0;
				while (current != NULL && idx < beg)
				{
					current = current->forward[0];
					idx++;
				}

				while (current != NULL && idx <= end)
				{
					offset += snprintf(output_buf+offset, sizeof(output_buf), "$%lu\r\n%s\r\n", strlen(current->value), current->value);
					current = current->forward[0];
					idx++;
				}				
			}
		}
		else if (c_str_eq(command, "ZCARD"))
		{
			char *zset_key = PSTR(cmd.tokens[1]);
			Entry *e = hashmap_get_entry(map, zset_key);
			snprintf(output_buf, sizeof(output_buf), ":0\r\n");
			if (e)
			{ 
				int total = e->sorted_set->size;
				snprintf(output_buf, sizeof(output_buf), ":%d\r\n", total);
			}
		}
		else if (c_str_eq(command, "ZSCORE"))
		{
			snprintf(output_buf, sizeof(output_buf), "$-1\r\n");
			char *zset_key = PSTR(cmd.tokens[1]);
			Entry *e = hashmap_get_entry(map, zset_key);
			if (e)
			{ 
				char *member_key = PSTR(cmd.tokens[2]);

				ZSetMember *member = zset_get(e->sorted_set, member_key);
				char t_buf[256];
				snprintf(t_buf, sizeof(t_buf), "%.015lf", member->value->key);
				snprintf(output_buf, sizeof(output_buf), "$%lu\r\n%s\r\n", strlen(t_buf), t_buf);
			}
		}
		else if (c_str_eq(command, "ZREM"))
		{
			char *zset_key = PSTR(cmd.tokens[1]);
			char *zset_member = PSTR(cmd.tokens[2]);
			snprintf(output_buf, sizeof(output_buf), ":0\r\n");
			Entry *e = hashmap_get_entry(map, zset_key);
			if (e)
			{
				ZSetMember *member = zset_get(e->sorted_set, zset_member);
				if (member)
				{
					skiplist_remove(e->sorted_set->list, member->value->key, zset_member);
					skiplist_traverse(e->sorted_set);
					snprintf(output_buf, sizeof(output_buf), ":1\r\n");
				}
			}			
		}

		else if (c_str_eq(command, "GEOADD"))
		{
			char *key = PSTR(cmd.tokens[1]);
			double longitude = atof(PSTR(cmd.tokens[2]));
			double latitude = atof(PSTR(cmd.tokens[3]));
			char *member = PSTR(cmd.tokens[4]);
			if (longitude < MIN_LONGITUDE || longitude > MAX_LONGITUDE || latitude < MIN_LATITUDE || latitude > MAX_LATITUDE)
			{
				write(client_sock, "-ERR invalid longitude,latitude pair\r\n" , strlen("-ERR invalid longitude,latitude pair\r\n"));
				continue;
			}
			int res = insert_into_sorted_set(key, member, coord_encode(latitude, longitude));
			snprintf(output_buf, sizeof(output_buf), ":%d\r\n", res);
		}

		else if (c_str_eq(command, "GEOPOS"))
		{
			char *key = PSTR(cmd.tokens[1]);
			snprintf(output_buf, sizeof(output_buf), "*1\r\n*-1\r\n");
			Entry *entries = hashmap_get_entry(map, key);
			int place_cnt = cmd.len - 2;
			int offset = snprintf(output_buf, sizeof(output_buf), "*%d\r\n", place_cnt);
			for (int i = 2; i < cmd.len; ++i)
			{
				char *member_key = PSTR(cmd.tokens[i]);
				ZSetMember *member = NULL;
				if (entries)
					member = zset_get(entries->sorted_set, member_key);

				if (member)
				{
					coordinates_t coords = decode_coord(member->value->key);

					char long_str[32];
					snprintf(long_str, 32, "%.15lf", coords.longitude);

					char lat_str[32];
					snprintf(lat_str, 32, "%.15lf", coords.latitude);


					offset += snprintf(output_buf + offset, sizeof(output_buf), "*2\r\n$%lu\r\n%s\r\n$%lu\r\n%s\r\n", strlen(long_str), long_str, strlen(lat_str), lat_str);
				}
				else
					offset += snprintf(output_buf + offset, sizeof(output_buf), "*-1\r\n");
			}
		}

		else if (c_str_eq(command, "GEODIST"))
		{
			const double EARTH_RADIUS_IN_METERS = 6372797.560856L;
			
			char *key = PSTR(cmd.tokens[1]);
			char *city1 = PSTR(cmd.tokens[2]);
			char *city2 = PSTR(cmd.tokens[3]);

			Entry *entries = hashmap_get_entry(map, key);

			ZSetMember *city1_data	 = NULL;
			if (entries)
				city1_data = zset_get(entries->sorted_set, city1);
			coordinates_t city1_coords = decode_coord(city1_data->value->key);
		
			ZSetMember *city2_data	 = NULL;
			if (entries)
				city2_data = zset_get(entries->sorted_set, city2);
			coordinates_t city2_coords = decode_coord(city2_data->value->key);

			if (city1_data == NULL || city2_data == NULL)
			{
				snprintf(output_buf, sizeof(output_buf), "$-1\r\n");
				write(client_sock, output_buf, strlen(output_buf));
				continue;
			}

			double distance_meters = get_distance(city1_coords, city2_coords);
			char dist_buf[32];
			snprintf(dist_buf, sizeof(dist_buf), "%.8lf", distance_meters);
			snprintf(output_buf, sizeof(output_buf), "$%lu\r\n%s\r\n", strlen(dist_buf), dist_buf);			
		}

		else if (c_str_eq(command, "GEOSEARCH"))
		{
			char *key = PSTR(cmd.tokens[1]);
			char *from_what = PSTR(cmd.tokens[2]);
			double longitude = atof(PSTR(cmd.tokens[3]));
			double latitude = atof(PSTR(cmd.tokens[4]));
			char *by_what = PSTR(cmd.tokens[5]);
			double search_radius = atof(PSTR(cmd.tokens[6]));
			char *unit = PSTR(cmd.tokens[7]);
			
			snprintf(output_buf, sizeof(output_buf), "*0\r\n");

			Entry *entries = hashmap_get_entry(map, key);

			if (entries == NULL)
			{
				write(client_sock, output_buf, strlen(output_buf));
				continue;
			}

			coordinates_t search_coor = {.latitude= latitude, .longitude = longitude};

			SkipList *list = entries->sorted_set->list;
			SortedSetNode *current = list->header->forward[0];

			char temp_buf[BUF_SIZE];
			int found = 0;
			int offset = 0;
			while (current != NULL)
			{
				coordinates_t city_coord = decode_coord(current->key);
				double dist = get_distance(search_coor, city_coord);

				if (dist <= search_radius)
				{
					offset += snprintf(temp_buf + offset, sizeof(temp_buf), "$%lu\r\n%s\r\n", strlen(current->value), current->value);
					found++;
				}
				current = current->forward[0];
			}

			snprintf(output_buf, sizeof(output_buf), "*%d\r\n%s", found, temp_buf);
		}
    else if (c_str_eq(command, "ACL"))
    {
      if (c_str_eq(cmd.tokens[1], "WHOAMI"))
      {
        if (hashmap_get(map, "userid:default") && !authenticated)
          strcpy(output_buf, "-NOAUTH Authentication required\r\n");
        else
          strcpy(output_buf, "$7\r\ndefault\r\n");
      } else if (c_str_eq(cmd.tokens[1], "GETUSER"))
      {
        char username[256];
        snprintf(username, sizeof(username), "userid:%s", PSTR(cmd.tokens[2]));
        char* pass = hashmap_get(map, username);
        if (pass)
          snprintf(output_buf, sizeof(output_buf), "*4\r\n$5\r\nflags\r\n*0\r\n$9\r\npasswords\r\n*1\r\n$%ld\r\n%s\r\n", strlen(pass), pass);
        else
          snprintf(output_buf, sizeof(output_buf), "*4\r\n$5\r\nflags\r\n*1\r\n$6\r\nnopass\r\n$9\r\npasswords\r\n*0\r\n");
      } else if (c_str_eq(cmd.tokens[1], "SETUSER"))
      {
        char hashed_pass[SHA256_BLOCK_SIZE * 2 + 1];
        get_hashed_str((const BYTE*) (PSTR(cmd.tokens[3]) + 1) /*skipping > */, hashed_pass);

        char username[256];
        snprintf(username, sizeof(username), "userid:%s", PSTR(cmd.tokens[2]));
        hashmap_put(map, username, hashed_pass, UINT64_MAX, TypeString);

        strcpy(output_buf, "+OK\r\n");
        authenticated = 1;
      }
    }
    else if (c_str_eq(command, "AUTH"))
    {
      strcpy(output_buf, "-WRONGPASS invalid username-password pair or user is disabled.\r\n");

      char username[256];
      snprintf(username, sizeof(username), "userid:%s", PSTR(cmd.tokens[1]));
      char* pass = hashmap_get(map, username);
      if (pass)
      {
        char hashed_pass[SHA256_BLOCK_SIZE * 2 + 1];
        get_hashed_str((const BYTE*) PSTR(cmd.tokens[2]), hashed_pass);
        if (strcmp(hashed_pass, pass) == 0)
        {
          strcpy(output_buf, "+OK\r\n");
          authenticated = 1;
        }
      }
    }
    else if (c_str_eq(command, "WATCH"))
    {
      if (transaction.active)
        strcpy(output_buf, "-ERR WATCH inside MULTI is not allowed\r\n");
      else
      {
        for (int i = 1; i < cmd.len; ++i)
          push_watched(&watch_head, PSTR(cmd.tokens[i]), client_sock);
        strcpy(output_buf, "+OK\r\n");
      }
    }
    else if (c_str_eq(command, "UNWATCH"))
    {
      clear_watch_list();
      strcpy(output_buf, "+OK\r\n");
    }

		write(client_sock, output_buf, strlen(output_buf));
	}

	close(client_sock);
	return NULL;
}

int main(int argc, char *argv[]) {

  setup_crash_handler();
	// Disable output buffering
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
	pthread_mutex_init(&lpop_mutex, NULL);

	map = hashmap_create();

	port = 6379;
	replication_port = 0;

  char cwd[PATH_MAX / 2];
  getcwd(cwd, sizeof(cwd));
  shput(config, "dir", cwd);
  shput(config, "appendonly", (char*) "no");
  shput(config, "appenddirname", (char*) "appendonlydir");
  shput(config, "appendfilename", (char*) "appendonly.aof");
  shput(config, "appendfsync", (char*) "everysec");

	for (int i = 1; i < argc; i+=2)
	{
		if (strncmp(argv[i], "--replicaof", strlen("--replicaof")) == 0)
		{
      shput(config, "replicaof", argv[i + 1]);
			sscanf(argv[i + 1], "%*s %d", &replication_port);
		}
		if (strncmp(argv[i], "--port", strlen("--port")) == 0)
		{
			port = atoi(argv[i+1]);
		}
		if (strncmp(argv[i], "--dir", strlen("--dir")) == 0)
		{
      shput(config, "dir", argv[i + 1]);
      mkdir((char*) argv[i + 1], 0755);
		}

		if (strncmp(argv[i], "--dbfilename", strlen("--dbfilename")) == 0)
		{
      shput(config, "dbfilename", argv[i + 1]);
		}
    if (strncmp(argv[i], "--appendonly", strlen("--appendonly")) == 0)
		{
      shput(config, "appendonly", argv[i + 1]);
		}
    if (strncmp(argv[i], "--appendfsync", strlen("--appendfsync")) == 0)
		{
      shput(config, "appendfsync", argv[i + 1]);
		}
    if (strncmp(argv[i], "--appenddirname", strlen("--appenddirname")) == 0)
		{
      shput(config, "appenddirname", argv[i + 1]);
      snprintf(cwd, PATH_MAX, "%s/%s", shget(config, "dir"), argv[i + 1]);
      mkdir((char*) cwd, 0755);
		}
    if (strncmp(argv[i], "--appendfilename", strlen("--appendfilename")) == 0)
		{
      append_only = 1;
      shput(config, "appendfilename", argv[i + 1]);
      snprintf(full_append_path, PATH_MAX, "%s/%s.1.incr.aof", cwd, argv[i + 1]);
      FILE* fp = fopen(full_append_path, "a");
      if (fp != NULL)
        fclose(fp);

      char manifest_path[PATH_MAX];
      snprintf(manifest_path, PATH_MAX, "%s/%s.manifest", cwd, argv[i + 1]);

      FILE* manifest_f = fopen(manifest_path, "r");
      if (manifest_f)
      {
        char play_file_name[PATH_MAX / 4];
        if (fscanf(manifest_f, "%*s %255s", play_file_name))
        {
          char play_file_path[PATH_MAX];
          snprintf(play_file_path, sizeof(play_file_path), "%s/%s", cwd, play_file_name);
          int fd = open(play_file_path, O_RDWR);
          int* fake_client_sock = (int*) memcpy(malloc(sizeof(int)), (int[]) { fd }, sizeof(int));
          handle_client(fake_client_sock);
        }
        fclose(manifest_f);
      }

      char filename[256];
      snprintf(filename, sizeof(filename), "file %s.1.incr.aof seq 1 type i", argv[i + 1]);
      
      fp = fopen(manifest_path, "wb");
      fwrite(filename, sizeof(char), strlen(filename), fp);
      if (fp != NULL)
        fclose(fp);
		}
	}

	DEBUG("Config[ArgDirName]: %s\n", shget(config, "dir"));
	DEBUG("Config[ArgFileName]: %s\n", shget(config, "dbfilename"));
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	DEBUG("Logs from your program will appear here!\n");


	int server_fd;
	struct sockaddr_in client_addr;
	socklen_t client_addr_len;
	//
	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd == -1) {
		DEBUG("Socket creation failed: %s...\n", strerror(errno));
		return 1;
	}
	
	// Since the tester restarts your program quite often, setting SO_REUSEADDR
	// ensures that we don't run into 'Address already in use' errors
	int reuse = 1;
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
		DEBUG("SO_REUSEADDR failed: %s \n", strerror(errno));
		return 1;
	}
	
	struct sockaddr_in serv_addr = { .sin_family = AF_INET ,
									 .sin_port = htons(port),
									 .sin_addr = { htonl(INADDR_ANY) },
									};
	
	if (bind(server_fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) != 0) {
		DEBUG("Bind failed: %s \n", strerror(errno));
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
		DEBUG("Listen failed: %s \n", strerror(errno));
		return 1;
	}
	
	DEBUG("Waiting for a client to connect...\n");
	client_addr_len = sizeof(client_addr);
	


	char redis_file_path[1024];
	snprintf(redis_file_path, sizeof(redis_file_path), "%s/%s", shget(config, "dir"), shget(config, "dbfilename"));
	

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
    int* client_sock_ptr = (int*) malloc(sizeof(int));
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
