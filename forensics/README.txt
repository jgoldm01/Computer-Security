Assignment 5: Forensics
Team 13: Thomas Strassner and Jeremy Goldman

Part 1: Images

We downloaded the three images from the website. We used the diff command to see
which two files were the same, and therefore identify the third one as the
outlier. We found that to be image B. 

We then used the command steghide -sf imgB.jpg -p pass to test passwords. none
of the ones we could think of worked, so we wrote a bash script to go through a
wordlist and test each word as a password. it looked somewhat like this: 

#!/bin/sh
for word in (<$wordlist.txt)
do
    steghide -sf imgB.jpg -p pass
done

In the middle of the execution, the terminal asked if we wanted to write a file
runme. We said yes, and after the script went through the wordlist we examined
the file runme. because of the name, we guessed it was an executable, so we
changed the permissions with “sudo chmod a+x runme” and ran the program. it
asked for our names, so we wrote in Jeremy, and it told us (specifically jeremy)
that we were doing a heckuva good job up to this point!

We also ran the command strings runme to see if there were any strings
associated with the file. one interesting one was blinky_the_wonder_chimp. So we
ran the file with that string as the first argument, (among other things), and
the program output that we should send you an email with a specific title line.
Of course, we couldn’t resist the temptation. 


Part 2: forensics on disk image

1. There are two disk partitions on this drive, one is windows and the other is
linux. The windows partition is fs format fat16, whereas the linux system is ext
file system.

2. There is a phone carrier involved. in the windows partition, there is a file
called LICENSE.broadcom which details the broadcom licensing. Broadcom is a
global corporation involved in semiconductor manufacturing and distribution, and
they are involved in the phone carrier industry. 

3. There are two operating systems on the disk:
Win95 FAT32
Kali Linux
     We know these because autopsy told us this information when we uploaded the
     disk  image. However, it only said Linux for the second one, and did not
     specify what distribution. We figured out it was Kali by looking in the
     /usr/share, where we found two directories named kali-defaults and
     kali-menu.

4. Within the usr/share/kali-menu directory there is an applications folder.
This contains the applications that kali comes with as an operating system.
Another application present is TiMidity++, a program which can play MIDI files
without a hardware synthesizer. Iceweasel, imagemagick, john the ripper,
wildmidi, wireshark, x11, apache, and firebird are present in the /etc/
directory. There are other applications such as nano and netcat, which we found
in the /bin/ directory. 

5. There is a root password. It is: princess

6. There are three other accounts besides the root. We were able to access two
of the passwords: 
account: stefani, password: iloveyou
account: judas, password: 0000000

7. What we have found clearly indicates that the owner of this disk is stalking
lady gaga, but we did not find any evidence of criminal intent or activity. 

8. The suspect deleted three image files before his arrest. We assume these were
images of lady gaga because they were in a directory with other images of lady
gaga. Another file, called “note.txt” was deleted via terminal commands. 

9. Yes, the suspect had pictures of the celebrity saved on their computer. We
found 17 pictures of her, including 3 deleted pictures.

10. Yes, the file lockbox.txt is an encrypted zip file. When attempting to unzip
it, we were prompted with a request for a password. before writing a script to
do this, we attempted a couple and succeeded with the word “gaga”. the file is
an mp4 of her singing the edge of glory on what is presumably a radio show. Why
would the owner encrypt this? Likely it was high treason…
We also found 2 encrypted files in the linux firmware, in the directory
/lib/firmware/vxge/
We were unable to decrypt them, but it seems that they are part of the firmware
of the computer, rather than files encrypted by the suspect.

11. Yes, they do want to go see her. Here are the dates and locations:

12/31/2014: 9:00 p.m. PST: The Chelsea at the Cosmopolitan of Las Vegas Las
                           Vegas, NV
2/8/2015: 9:30 p.m. PST: Wiltern Theatre, Los Angeles, CA
5/30/2015: 7:30 p.m. PST: Hollywood Bowl, Hollywood, CA

12. Stefani Germanotta A.K.A. Lady Gaga
