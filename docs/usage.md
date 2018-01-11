# choppy usage  


### Command Line

generate cryptographic key file (key.txt)

    choppy gen -k

create 10 partitions of infile.txt, randomize partition size by 50% and encrypt with key file

    choppy chop infile.txt -n 10 -w 50 --use-key -i key.txt

decrypt partitions and merge to reassemble original file

    choppy merge *.chp.* --use-key -i key.txt
