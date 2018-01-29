## choppy: Command Line Usage  

### Overview:  
Choppy generates encrypted file partitions which can be decrypted and reassembled using a shared secret key. Filenames and extensions can be changed as needed and do not affect the reassembly step.  

All cryptographic operations are handled by the [pyca/cryptography](https://cryptography.io/en/latest/) library. My knowledge of cryptography is limited but I know enough to not write my own crypto functions.


### Choptions:  

- number of partitions to generate for each input file (default = 10)  

        -n 10

- randomize partition file sizes by 1-99 % of the equally distributed file size (default = 0)  

        -w, --wobble 25

- use random file names for partitions instead of sequential numeric  

        -r, --randfn


### Key / Password Options:  

[Fernet symmetric cryptography](https://cryptography.io/en/latest/fernet/)  

Choppy uses symmetric authenticated cryptography. A shared, secret key is used for both the encryption and decryption of a file. Keys can be saved as plain text or derived as needed using password and salt input.  

Keys are deterministically derived from a password, salt, and iteration count.


##### Using Keys:  

1. **Generate** text file containing random, cryptographic key (key.txt):  

        choppy gen -k

2. Create (**chop**) 10 partitions of infile.txt, encrypt with key file:  

        choppy chop infile.txt --use-key -i key.txt

3. Decrypt partitions and **merge** to reassemble original file:  

        choppy merge *.chp.* --use-key -i key.txt


##### Using Passwords:  

Passwords are always used in combination with a salt file and iteration count. All 3 pieces of information are necessary for deriving a useable key. By default, choppy sets iterations at 100,000.  

0. [optional] **Generate** text file containing random plain text password with 16 characters:

        choppy gen --pw 16

1. **Generate** salt file of 32 random bytes.

        choppy gen --salt 32

2. Create (**chop**) 10 partitions of infile.txt, encrypt with password, salt file, iterations:

    - Password input via text file:

            choppy chop infile.txt --use-pw -i pw.txt --salt salt.txt --iterations 100000

    - Or enter password as text in secure prompt:

            choppy chop infile.txt --use-pw --salt salt.txt --iterations 100000

3. Decrypt partitions and **merge** to reassemble original file:  

    - Password input via text file:

            choppy merge *.chp.* --use-pw -i pw.txt --salt salt.txt --iterations 100000

    - Or enter password as text in secure prompt:

            choppy merge *.chp.* --use-pw --salt salt.txt --iterations 100000


##### Deriving keys from password, salt, iterations:  

**Derive** key and write to a text file. Files encrypted via password/salt can be decrypted using the derived key.   

- Password input via text file:

        choppy derive --use-pw -i pw.txt --salt salt.txt --iterations 100000

- Or enter password as text in secure prompt:

        choppy derive --use-pw --salt salt.txt --iterations 100000


----  
