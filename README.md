# Redis Clone in C

A Redis clone implementation in C, built as part of the CodeCrafters "Build Your Own Redis" challenge. This project implements core Redis functionality including data structures, persistence, replication, and pub/sub messaging.

## Features

### ✅ Implemented Features

- **Stages**: Basic Redis server setup and command handling
- **Lists**: Redis LIST data type operations (LPUSH, RPUSH, LPOP, RPOP, LLEN, etc.)
- **Streams**: Redis STREAM data type with XADD, XREAD, XRANGE commands
- **Transactions**: MULTI/EXEC transaction support for atomic command execution
- **Replication**: Master-slave replication with PSYNC protocol
- **RDB Persistence**: Redis Database file format support for data persistence
- **Pub/Sub**: Publish/Subscribe messaging with PUBLISH, SUBSCRIBE, UNSUBSCRIBE

## Getting Started

### Prerequisites

- GCC compiler
- Unix-like environment (Linux, macOS, WSL)

### Building and Running

The project includes a build script that compiles and runs the Redis server:

```bash
./your_program.sh
```

This script will:
1. Compile the C source code in `app/server.c`
2. Start the Redis server on the default port (6379)

### Testing with Redis CLI

Once the server is running, you can connect using the standard Redis CLI:

```bash
redis-cli
```

Or telnet for basic testing:

```bash
telnet localhost 6379
```

## Project Structure

```
.
├── app/
│   └── server.c          # Main Redis server implementation
├── codecrafters.yml      # CodeCrafters configuration
├── README.md            # This file
└── your_program.sh      # Build and run script
```

## Supported Commands

### Basic Commands
- `PING` - Test server connectivity
- `ECHO` - Echo messages
- `SET key value [EX seconds]` - Set key-value pairs with optional expiration
- `GET key` - Get value by key
- `EXISTS key` - Check if key exists
- `DEL key` - Delete key
- `INCR key` - Increment integer value

### List Commands
- `LPUSH key element` - Push element to left of list
- `RPUSH key element` - Push element to right of list
- `LPOP key` - Pop element from left of list
- `RPOP key` - Pop element from right of list
- `LLEN key` - Get list length

### Stream Commands
- `XADD key ID field value` - Add entry to stream
- `XRANGE key start end` - Get range of stream entries
- `XREAD [STREAMS] key ID` - Read from stream

### Transaction Commands
- `MULTI` - Start transaction
- `EXEC` - Execute transaction
- `DISCARD` - Discard transaction

### Pub/Sub Commands
- `PUBLISH channel message` - Publish message to channel
- `SUBSCRIBE channel` - Subscribe to channel
- `UNSUBSCRIBE channel` - Unsubscribe from channel

### Replication Commands
- `REPLCONF` - Replication configuration
- `PSYNC replicationid offset` - Partial synchronization

## Implementation Details

### Protocol
- Implements Redis Serialization Protocol (RESP)
- Handles both simple strings and bulk strings
- Supports pipelined commands

### Data Structures
- Hash tables for key-value storage
- Linked lists for Redis lists
- Custom stream implementation
- Expiration tracking with timestamps

### Persistence
- RDB file format support
- Periodic snapshots
- Loading from existing RDB files

### Replication
- Master-slave architecture
- Command propagation
- Partial resynchronization support

## Development

### Code Organization
The main server logic is contained in `app/server.c`, which includes:
- Event loop implementation
- Command parsing and execution
- Data structure management
- Network protocol handling

### Adding New Features
1. Implement command handler in `server.c`
2. Add command to the command table
3. Test with Redis CLI
4. Update documentation

## Testing

Test the implementation using standard Redis tools:

```bash
# Basic connectivity
redis-cli ping

# Set and get operations
redis-cli set mykey "Hello Redis"
redis-cli get mykey

# List operations
redis-cli lpush mylist "item1" "item2"
redis-cli lrange mylist 0 -1

# Pub/Sub
# Terminal 1:
redis-cli subscribe mychannel

# Terminal 2:
redis-cli publish mychannel "Hello World"
```

## Contributing

This is a learning project built for the CodeCrafters challenge. Feel free to:
- Report bugs or issues
- Suggest improvements
- Submit pull requests

## License

This project is built as part of the CodeCrafters educational platform. See CodeCrafters terms for usage details.

## Acknowledgments

- [CodeCrafters](https://codecrafters.io) for the excellent Redis challenge
- Redis documentation and source code for reference
- The Redis community for comprehensive protocol documentation