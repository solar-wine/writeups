# HACK-A-SAT 3: 150 File Status

* **Category:** Turnstile Services
* **Points:** 10000
* **Description:**

```text
The flight software got too cumbersome to distribute by HTTP so we threw up a homebrew FTP server on this machine.
It is running under an account named hasftpd with password L@bm0nkey2delta.
```

## Write-up

_Write-up by Solar Wine team_

Connecting to the FTP server using the provided user and password, the binary of the FTP server can be retrieved using passive mode.

```shell
$ ftp 10.23.223.25:21
User: hasftpd
Password: L@bm0nkey2delta
ftp> passive
Passive mode on.
ftp> get hasftpd
```

### Vulnerabilities

The binary is an x86-64 ELF file implementing a FTP server with some custom commands:

```text
Commands supported:
* APPE (not working due to active mode not connecting back to us)
* CDUP
* CWD
* DELE
* EXEC (custom)
* FEAT
* FREE (custom)
* LIST
* MKD
* NLST
* PASS
* PASV
* PORT
* PWD
* QUEU (custom)
* QUIT
* RETR
* RMD
* RNFR
* RNTO
* STOR (not working due to active mode)
* STOU (not working due to active mode)
* SYST
* TYPE
* USER
* VIEW
```

The client is represented by a structure `client_ctxt`. Here are the first fields:

```text
00000000 client_ctxt     struc ;
00000000 login           db 16 // char[16] login
00000010 type            db 16 // char[16] type
00000020 homedir         dq ?
00000028 current_dir     dq ?
00000030 socket          dd ?
00000034 data_socket     dd ?
00000038 user_done       dd ?
0000003C user_exists     dd ?
00000040 logged          dd ?
00000044 field_44        dd ?
```

The `home` field is the folder in which accessible data are placed (here ``/home/hasftpd/``), and `current_dir` the current directory. Thus, when `current_dir` is modified, it must start by `current_dir`. It seems there is no trivial bypass for this check.

#### First vulnerability: directory listing

The `LIST` command takes a folder path as argument and returns the list of files in the folder. The bug is that the command doesn't check that the argument is behind `homedir`, so we can ask it to list any folder in the filesystem.

Using this vulnerability, the path of the flag can be retrieved as well as the path of important satellite files:

```text
/home/hasfsw/flag.txt
/home/hasfsw/cpu1/core-cpu1
/home/hasfsw/cpu1/cf/sms.so
/home/hasfsw/cpu1/cf/spaceflag.so
/home/hasfsw/cpu1/cf/mon.so
/home/hasfsw/cpu1/cf/puzzlebox.so
/home/hasfsw/cpu1/cf/radio.so
...
```

The ``RETR`` command however does check that the input path must start with `homedir` and then can't be used to download the files.

#### Second vulnerability: info leak

The `TYPE` command takes a string as argument and store it in the `type` field of the client context. Then, it returns that string to the client, with this code:

```c
cmd_type()
{ // ...
    send("Command okay: %s", s->type_data);
}
```
However, it does not validate that the input string ends with a NULL byte, and we see that the way it is formatted (with %s) we are able to leak the field following `type`, which is the address of the `homedir` string.

#### Third vulnerability: use-after-free and/or double free

The last vulnerability used is a Use-After-Free and double free in a custom command ``FREE``.

The custom feature of the FTP server is a queue implementation of FTP commands. The user can embed commands with the ``QUEU`` command and run them later using the ``EXEC`` command.

The commands are stored in a linked list and the command ``FREE`` allows to free one command in the queue, selected using an ID.

Here is the `FREE` command handler:

```c
id = atoi(req->req_data);
for ( ptr = queue_list_head; ptr; ptr = (queu_obj *)ptr->next )
{
    if ( id == i )
    {
        free(ptr);
        break;
    }
    ++i;
}
```

The issue is that the freed command is not removed from the linked list and can be used (with  ``EXEC``) and double freed by calling ``FREE`` with the same ID.

### Exploitation

The goal of the exploit is to change the content of `homedir`, which is an allocated string which we have the address of.

The first step is to control a field `next` of an object in the linked list. This is achieved by using the
generic ``house_of_botcake`` technique (requiring a double free) to coalesce small bins chunks into a larger one that will overlap two entries of the queue. By writing into this new large chunk (by reallocating the object with controlled data) we can control the `next` pointer of one object of the linked list. We set the value to the address of `homedir`. Thus, `homedir` object is then reachable by walking the linked list, and can be freed with the `FREE` command.

It is then possible to reallocate the `homedir` object with controlled data, allowing us to replace its value by '/'.

With that, using the command ``RETR`` allows us to download any file on the server filesystem.

Flag is: `flag{/odi9LL/XQ7FuOJk}`
