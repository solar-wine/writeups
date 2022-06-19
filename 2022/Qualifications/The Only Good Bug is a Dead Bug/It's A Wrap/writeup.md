# HACK-A-SAT 3: It's A Wrap

* **Category**: The Only Good Bug is a Dead Bug
* **Points:** 43
* **Solves:** 108
* **Description:**

> Do you like inception?

> You'll need these files to solve the challenge.
>
> - https://static.2022.hackasat.com/n50xglah3x4cbisdicrwnc2iw4sq

## Write-up

_Write-up by Solar Wine team_

First, connect to the challenge using nc.
This is what the service asks us when we provide it with our team ticket:

```shell
$ echo 'ticket{victor657699zulu3:GNTSOYfh-bXQ7Wh4tuW0mJ8tqTaHzmOWioZAsxu5A9LC1CIpvapSHV-olGPqCCLj8Q}' | nc its_a_wrap.satellitesabove.me 5300
Ticket please:
You have inherited a simple encryption dll from previous project
that you must use.  It used to work but now it seems it does not.
Given the encryption matrix:
| -3 -3 -4 |
|  0  1  1 |
|  4  3  4 |
...and the phrase 'HACKASAT3'.

 Enter the phrase in standard decimal ASCII
 and the resulting encrypted list
    Example: 'XYZ': 88,89,90
             Encrypted list: 1,2,3,4,5,6,7,8,9
 Entered phrase:  1,2,3,4,5,6,7,8,9
 Encrypted phrase:  1,2,3,4,5,6,7,8,9
 Entered phrase:  1,2,3,4,5,6,7,8,9
 Encrypted phrase:  1,2,3,4,5,6,7,8,9

Computing encrypted phrase...
```

Unfortunately, it seems that the challenge was broken. It accepts any phrase to encrypt and not only the 'HACKASAT3' asked one.
While some of us were decompiling the .pyc file and trying to implement the matrix cryptosystem, one of us were able to validate the challenge by giving it a 0's decimal ASCII phrase.

```shell
Enter phrase > 0,0,0,0,0,0,0,0,0
Enter encrypted phrase> 0,0,0,0,0,0,0,0,0
```

This phrase and encrypted phrase validated the challenge.

```shell
$ echo 'ticket{victor657699zulu3:GNTSOYfh-bXQ7Wh4tuW0mJ8tqTaHzmOWioZAsxu5A9LC1CIpvapSHV-olGPqCCLj8Q}' | nc its_a_wrap.satellitesabove.me 5300
Ticket please:
You have inherited a simple encryption dll from previous project
that you must use.  It used to work but now it seems it does not.
Given the encryption matrix:
| -3 -3 -4 |
|  0  1  1 |
|  4  3  4 |
...and the phrase 'HACKASAT3'.

 Enter the phrase in standard decimal ASCII
 and the resulting encrypted list
    Example: 'XYZ': 88,89,90
             Encrypted list: 1,2,3,4,5,6,7,8,9
 Enter phrase> 0,0,0,0,0,0,0,0,0
 Enter encrypted phrase> 0,0,0,0,0,0,0,0,0
 Entered phrase:  0,0,0,0,0,0,0,0,0
 Encrypted phrase:  0,0,0,0,0,0,0,0,0

Computing encrypted phrase...

----------------------------------
Congradulations you got it right!!

Here is your flag:  flag{victor657699zulu3:GIW6DSLTLAeZDiA9uizlnjdlxUJkuDRs1SEoNBb3od2Yn9zdX7QYORlWwAQaq8iW5v2LO4bGWwv3thXSGR1s0jo}
----------------------------------
```

