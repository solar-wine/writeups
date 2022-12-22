# HACK-A-SAT 3: Game access flag

* **Category:** Turnstile Services
* **Points:** 10000
* **Description:**

Successfully connecting and getting a commande shell on game infrastructure at the start of the game.

## Write-up

_Write-up by Solar Wine team_

Just connect to the game server using provided SSH access, then cat the flag.

```shell
solarwine@production-test:~/scripts$ cat flag.txt
flag{dmSFBV6wuwl5F6Kj}
flag=dmSFBV6wuwl5F6Kj
dmSFBV6wuwl5F6Kj
```

Flag is: `flag{dmSFBV6wuwl5F6Kj}`
