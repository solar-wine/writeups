# HACK-A-SAT 3: Leggo my Steggo!

* **Category**: Crypto Category Placeholder Name
* **Points:** 121
* **Solves:** 30
* **Description:**

> We've been running this satellite that has the same command mnemonic as an old Hack-a-Sat 2020 satellite - but now its infected with something.
>
> In our last communication it dumped out all these files.
>
> Re-gain authority over the satellite
>
> The satellite seems to still respond to the commands mnemonics we used before but replies in a strange way.
>
> https://github.com/cromulencellc/hackasat-final-2020/tree/master/solvers/c4/solver_ruby_scripts

> You'll need these files to solve the challenge.
>
> - https://static.2022.hackasat.com/e57q8n0po2v67dglp44q7j6kqlov

## Write-up

_Write-up by Solar Wine team_

First, connect to the challenge via nc.
This is what the service asks us when we provide it with our team ticket:

```shell
$ echo 'ticket{uniform258749delta3:GM36VW2ZPK-zL-h_r1CMzHsQyBecBS2NGFK5CialLzOZNp1TyOnRc_1qzXV3k_meLA}' | nc leggo.satellitesabove.me 5300
Ticket please:
Can you regain control!
CMD>some_garbage_command
----INVALID------
```

This challenge ask us to re-gain authority over the satellite.
We tried several commands but nothing worked.

Inside the provided archive we found 10 satellite pictures
The title of the challenge contains `steggo`, so maybe there is some steganography involved.

```shell
$ steghide extract -sf boston.jpg -xf out.txt
Entrez la passphrase:
Ecriture des donnees extraites dans "out.txt".
$ cat out.txt
4aada52c9abb92d32c57007091f35bc8
```

There is no passphrase, just let it empty.
Repeating the operation for each file and we find:

```
boston   > 4aada52c9abb92d32c57007091f35bc8
chicago  > a6ec1dcd107fc4b5373003db4ed901f3
la       > ae7a2a6b7b583aa9cee67bd13edb211e
miami    > 1312798c840210cd7d18cf7d1ff64a40
nyc      > e115d6633cdecdad8c5c84ee8d784a55
oahu     > Use the command mnemonic that outputs moon.png
portland > 20b7542ea7e35bf58e9c2091e370a77d
sf       > f24b6a952d3f0a8f724e3c70de2e250c
slc      > 09e829c63aff7b72cb849a92bf7e7b48
vegas    > 7cef397dfa73de3dfedb7e537ed8bf03
```

Output seems to be a MD5 hash.
We could reverse hashes with <https://crackstation.net/>

```
Hash                             Type  Result
4aada52c9abb92d32c57007091f35bc8  md5  beanpot
a6ec1dcd107fc4b5373003db4ed901f3  md5  deepdish
ae7a2a6b7b583aa9cee67bd13edb211e  md5  cityofangels
1312798c840210cd7d18cf7d1ff64a40  md5  springbreak
e115d6633cdecdad8c5c84ee8d784a55  md5  fuhgeddaboudit
20b7542ea7e35bf58e9c2091e370a77d  md5  stayweird
f24b6a952d3f0a8f724e3c70de2e250c  md5  housingmarket
09e829c63aff7b72cb849a92bf7e7b48  md5  skiparadise
7cef397dfa73de3dfedb7e537ed8bf03  md5  letsgolasvegas
```

Following the link provided in the description, <https://github.com/cromulencellc/hackasat-final-2020/tree/master/solvers/c4/solver_ruby_scripts> and the hint `Use the command mnemonic that outputs moon.png`, we tried several commands on the satellite.
Only `TAKE_IMG` and `PLAYBACK_FILE` seemed to work, the satellite answered with a question, a string that looks like a SHA256 hash.

```shell
CMD>PLAYBACK_FILE
04ca7d835e92ae1e4b6abc44fa2f78f6490e0058427fcb0580dbdcf7b15bbb55?
>>0
Wrong
```

```shell
CMD>TAKE_IMG
983b1cc802ff33ab1ceae992591f55244538a509cd58f59ceee4f73b6a17b182?
>>
```

Investigate the pictures inside the archive again and you will find that the asked sha256 match a picture:

```shell
$ sha256sum *
d6bc6fbee628c3278ef534fd22700ea4017914c2214aa86447805f858d9b8ad4  boston.jpg
04ca7d835e92ae1e4b6abc44fa2f78f6490e0058427fcb0580dbdcf7b15bbb55  chicago.jpg
242f693263d0bcc3dd3d710409c22673e5b6a58c1a1d16ed2e278a8d844d7b0b  la.jpg
2aa0736e657a05244e0f8a1c10c4492dde39907c032dba9f3527b49873f1d534  miami.jpg
983b1cc802ff33ab1ceae992591f55244538a509cd58f59ceee4f73b6a17b182  nyc.jpg
7e03349fe5fa4f9e56642e6787a0bfda27fb4f647e3c283faaf7bd91dbfd1d39  oahu.jpg
b4447c4b264b52674e9e1c8113e5f29b5adf3ee4024ccae134c2d12e1b158737  portland.jpg
f37e36824f6154287818e6fde8a4e3ca56c6fea26133aba28198fe4a5b67e1a1  sf.jpg
088f26f7c0df055b6d1ce736f6d5ffc98242b752bcc72f98a1a20ef3645d05c1  slc.jpg
3b20a3b5b327c524674ca5a8310beb2d9efc5c257e60c4a9b0709d41e63584a3  vegas.jpg
```

Put all together and provide the reversed MD5 hash of the picture as an answer to the satellite's question.
Unfortunately, we didn't get the flag with the `TAKE_IMG` command:

```shell
$ echo 'ticket{uniform258749delta3:GM36VW2ZPK-zL-h_r1CMzHsQyBecBS2NGFK5CialLzOZNp1TyOnRc_1qzXV3k_meLA}' | nc leggo.satellitesabove.me 5300
Ticket please:
Can you regain control!
CMD>TAKE_IMG
983b1cc802ff33ab1ceae992591f55244538a509cd58f59ceee4f73b6a17b182?
>>fuhgeddaboudit
Thank you
f37e36824f6154287818e6fde8a4e3ca56c6fea26133aba28198fe4a5b67e1a1?
>>housingmarket
Thank you
3b20a3b5b327c524674ca5a8310beb2d9efc5c257e60c4a9b0709d41e63584a3?
>>letsgolasvegas
Thank you
088f26f7c0df055b6d1ce736f6d5ffc98242b752bcc72f98a1a20ef3645d05c1?
>>skiparadise
Thank you
d6bc6fbee628c3278ef534fd22700ea4017914c2214aa86447805f858d9b8ad4?
>>beanpot
Thank you
You did it
I'm still not giving you the satellite back
```

But we got the flag with the `PLAYBACK_FILE` command:

```shell
$ echo 'ticket{uniform258749delta3:GM36VW2ZPK-zL-h_r1CMzHsQyBecBS2NGFK5CialLzOZNp1TyOnRc_1qzXV3k_meLA}' | nc leggo.satellitesabove.me 5300
Ticket please:
Can you regain control!
CMD>PLAYBACK_FILE
3b20a3b5b327c524674ca5a8310beb2d9efc5c257e60c4a9b0709d41e63584a3?
>>letsgolasvegas
Thank you
242f693263d0bcc3dd3d710409c22673e5b6a58c1a1d16ed2e278a8d844d7b0b?
>>cityofangels
Thank you
04ca7d835e92ae1e4b6abc44fa2f78f6490e0058427fcb0580dbdcf7b15bbb55?
>>deepdish
Thank you
b4447c4b264b52674e9e1c8113e5f29b5adf3ee4024ccae134c2d12e1b158737?
>>stayweird
Thank you
f37e36824f6154287818e6fde8a4e3ca56c6fea26133aba28198fe4a5b67e1a1?
>>housingmarket
Thank you
OK you can have the satellite back
flag{uniform258749delta3:GJs9lhhGq_0kjQfvR6-78J851hO5zmFdtDDM5Nb83dAMW9QvVhlxM13FvE1FSYSAvnnPCxoXicV4Sa2hpw5JZfg}
```

