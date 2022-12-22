# HACK-A-SAT 3: Sacred Ground

* **Category:** Ground Station Access
* **Points:** 3400 per Ground Station on first connection
* **Description:**

Same as [Coffee Ground challenge](../Coffee%20ground/writeup.md).

## Write-up

_Write-up by Solar Wine team_

Service running on port 13100.

The service allows us to ask for the key of 5 Ground Stations: Melbourne,
Maspalomas, Tokyo, Kathmandu and Hawaii. However, the keys are sent encrypted.
The server also provides an interface for us to send an encrypted key and that
returns the name of the corresponding Ground Stations.

Modifying the encrypted key before sending it to the service allows us to
retrieve much important information:

* The cipher uses a block size of 16 bytes;
* The cipher is not authenticated;
* The service checks the padding of the decrypted content and outputs an error
  if there is a problem with it.

By assuming that the underlying cipher is using the standard [PKCS7 padding
scheme](https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7) and
the [Cipher Block
Chain](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC))
mode of operation, one can use a [padding oracle
attack](https://en.wikipedia.org/wiki/Padding_oracle_attack#Padding_oracle_attack_on_CBC_encryption) to retrieve the cleartext content, one byte at a time.

Using this attack gives password to connect to new Ground Stations,
for example:

* Melbourne: `whackyauctionclumsyeditorvividly`,
* Maspalomas: `oxygenlettucereprintmatchbookbroiler`,
* Tokyo: `comradeshindigscratchfreeloadtributary`,
* Kathmandu: `slicereveryonecrewmateantidotebannister`,
* Hawaii: `awokefacialheadlocklandedexpectant`.

These passwords are changing once in a while and the solving script can be run
again at any time to retrieve the current passwords.
