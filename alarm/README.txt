README
Jeremy Goldman
10/7

The requirements ofthe project have been met, though they are not perfect and do
not work exactly precisely in every instance. For instance, the credit card in
plaintext recognizes strings that start with a 3-6(the starting integers for
major credit card companies), and that has the format xxxx xxxx xxxx xxxx or 
xxxx_xxxx_xxxx_xxxx, given that x is an integer. the possibility of 16 straight
integers yielded too many false positives, so I decided to not notify the user
in that case. 

A null scan is recognized by multiple packets from the same ip address with no
flags

A xmas scan is recognized by the specific flag combination typical to xmas scans
coming from the same ip address

credit card numbers are recognized in the manner described above

the web server analysis works mainly through string parsing; each line of the
log has a specific format and each element is in a specific order in the line. I
was able to use this to look for http errors, and see if the software sending
the request was not only a web browser, but also an nmap scan. I believe this
and shellcode detection was implemented correctly. 

Each function is documented above the declaration. 

I collaborated/discussed with Louis Ades

I spent approximately 10 hours on this assignment

QUESTIONS:
1. I believe the heuristics used in this assignment are okay. they will detect
the most basic of incidents, executed in the most obvious of ways. its not the
most comprehensive alarm system, of course, but it is a prototype, so to speak.
there are countless other breaches of privacy that this project does not even
touch, and countless ways for attackers to hide their attacks so this system
could not detect them. 

2. if I had more time, I would let the system detect when someone is scanning
through the user's ports, regardless of which type of scan or flags used.
something is usually up if there are requests from the same ip address from
ports 1-10000. I would also maybe allow the user to putin his/her password into
the system and see if that is being sent plaintext over the internet. 
