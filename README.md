avwhy
=====

A script to reverse-engineer anti-virus signatures

This script tries to answer why is antivirus flagging something as malicious.
It uses simple (yet effective) method of fuzzing one byte at a time and probing
the detection. In other words, it attempts to reverse-engineer the detection
signature. It can be useful, for example, to prove a false positive or to find
where the malicious part is being hidden.

Currently supported scanners (implementation of any other scanner is trivial!):

MS Security Essentials (Windows)
McAfee uvscan (Linux)

WARNING: DON'T SCAN ARCHIVES AND PACKED FILES! You must unpack everything, such
as:

- UPX and other packers for executable files
- in case of installers the AV is also looking inside and detecting just one
of the files that are archived within the installer. Install everything and
figure out which file is detected. Then test it.
- PDFs need to be uncompressed and "decrypted" as well (see tools as pdftk,
PDFStreamDumper etc.)

If you don't unpack, the script will probably just find the compression / packer
signature.

TODO: implement more engines. It is very easy - just find a regexp for scanner
output and the command line for invoking the scanner, then create a new class
that will inherrit from AVscanner and implement 3 short methods + constructor
(please see examples for McAfee and MS). 
