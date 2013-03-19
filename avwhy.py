#!/usr/bin/python
#
__description__ = 'avwhy, use it to reverse engineer antivirus signatures'
__author__ = 'Andrzej Dereszowski'
__version__ = '0.0.1'
__date__ = '2012/07/01'
__minimum_python_version__ = (2, 5, 1)
__maximum_python_version__ = (3, 1, 2)

"""
    This is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version. avwhy is distributed in the hope tha 
    it will be useful, but WITHOUT ANY WARRANTY. Use it at your own risk

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

"""

import os, sys, subprocess, re, glob
from optparse import OptionParser

FILTER = ''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])

def hexdump(offset, src, length=16):
        result = []
        for i in xrange(0, len(src), length):
                s = src[i:i+length]
                hexa = ' '.join(["%02X" % ord(x) for x in s])
                printable = s.translate(FILTER)
                result.append("%08X   %-*s   %s\n" % (offset+i, length*3, hexa, printable))
        return ''.join(result)

###
# Base class. All scanner-specific classes inherrit from it
#

class AVscanner:
        def __init__(self, filename, batchSize, initialOffset, fuzzfolder):
                self.filename = filename
                self.batchSize = batchSize
                self.currentResults = {}
                self.rawResults = {}
                self.nextOffset = initialOffset
                self.activeOffset = initialOffset
                self.last = 0
                s = open(self.filename, "rb")
                self.buffer = s.read()
                self.length = len(self.buffer)
                s.close()
                self.fuzzfolder = fuzzfolder
                if not os.path.exists(self.fuzzfolder):
                        os.mkdir(self.fuzzfolder)
                if not os.path.isdir(self.fuzzfolder):
                        sys.stderr.write("fuzz folder %s exists and is not a directory" % self.fuzzfolder)
                        sys.exit(3)
        ###
        # public method
        # prepares and scans the next batch of fuzzed files
        #

        def getNext(self):
                # prepare for next batch
                self.clear()
                # create a batch of fuzzed files
                self.fuzz()
                # run the scanner on these files
                self.scan()
                # parse the output of the scanner and store unified results
                self.parse()
                # link adjacent bytes to strings
                self.rawToCurrent()     
                # return unified results
                return self.currentResults

        ###
        # changes the bitmap of detection offsets
        # to binary strings
        #

        def rawToCurrent(self):
                counting = 0
                currentResults = {} 
                for i in range(self.activeOffset, self.nextOffset):
                        if self.rawResults[i] == True:        
                                if not counting: 
                                        counting = 1
                                        currentResults[self.activeOffset] = {} 
                                        currentResults[self.activeOffset]['text'] = self.buffer[i]
                                        currentResults[self.activeOffset]['length'] = 1
                                else:
                                        currentResults[self.activeOffset]['text'] += self.buffer[i]
                                        currentResults[self.activeOffset]['length'] +=1
                        else:
                                if counting:
                                        counting = 0
                                        self.currentResults[self.activeOffset] = currentResults[self.activeOffset]
                                self.activeOffset = i   
                if self.last and counting == 1: 
                        self.currentResults[self.activeOffset] = currentResults[self.activeOffset]

        def cleanTmp(self):
                for i in glob.glob(self.fuzzfolder + "/" + "tmpfile*"):
                        os.unlink(i)
        
        ###
        # prepares for the next batch
        #

        def clear(self):
                self.cleanTmp()
                self.currentResults = {} 
                self.currentOffset = self.nextOffset
                if self.currentOffset + self.batchSize > self.length - 1:
                        self.nextOffset = self.length
                        self.last = 1
                else:
                        self.nextOffset = self.currentOffset + self.batchSize

        ###
        # prepares batchSize of fuzzed files in the fuzzfolder
        # to be scanned by one invocation of the scanner
        #

        def fuzz(self):
                for i in range(self.currentOffset, self.nextOffset):
                        new = ""
                        pos = 0
                        for c in self.buffer:
                                x = ord(c)
                                if pos == i:
                                        char = c
                                        x = (x + 1) % 256
                                        offset_next = pos
                                new += chr(x)
                                pos = pos + 1
                        tmpfile = self.fuzzfolder + "/" + "tmpfile_%08X" % i
                        d = open(tmpfile, "wb")
                        d.write(new)
                        d.close()

        ###
        # test on probability if scanner just calculates the cryptographic
        # checksum of the file as a detection (or size)
        # not 100% sure but gives a good guess
        #

        def ishash(self):
                # append one signle byte first
                curr_filename = self.filename
                # temporarily change self.filename to modified file
                self.filename = self.fuzzfolder + "/" + "tmpfile_hashtest"
                d = open(self.filename, "wb")
                d.write(self.buffer)
                d.write("\x0a")         # adding one more signle byte at the end
                d.close()
                ret = self.ismalicious()
                os.unlink(self.filename)
                self.filename = curr_filename
                return ret

###
# MS Security Essentials
#

class MSScanner(AVscanner):
        def __init__(self, batchSize, fuzzfolder, initialOffset, filename):
                # currently, MS scanner only supports batch size of 1
                # because when sanning a folder it only gives information
                # on how many threats it found, and not in which files.
                # Slow, but doable (takes few hours to scan 100k file on a fast machine)
                AVscanner.__init__(self, batchSize = 1, fuzzfolder=fuzzfolder, initialOffset=initialOffset, filename=filename)                
                sys.stderr.write("[i] For MS Security Essentials batch size is always forced to 1\n")       

        ###
        # parses the output of the scanner
        # defines the regexp to discern detected and undetected
        #

        def parse(self):        
                self.rawResults[self.currentOffset] = True
                for line in self.scannerOutput:
                        if re.search('found 1 threats', line):
                                self.rawResults[self.currentOffset] = False
                                
        ###
        # invokes the scanner and stores output in self.scannerOutput        
        # tests multiple files (not in case of MS, this is an exception)
        #       
        
        def scan(self):
                absfuzz = os.path.abspath(self.fuzzfolder) # MS needs full path name
                command = ['C:\\Program Files\\Microsoft Security Client\\MpCmdRun.exe',
                           '-Scan', '-ScanType', '3', '-File',  absfuzz + "\\tmpfile_%08X" % self.currentOffset]
                p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                self.scannerOutput = []
                while(True):
                        retcode = p.poll() #returns None while subprocess is running
                        self.scannerOutput.append(p.stdout.readline())        
                        if(retcode is not None):
                                break

        ###
        # invokes the scanner and stores output in self.scannerOutput        
        # tests just one signle file 
        # 

        def ismalicious(self):
                absfile = os.path.abspath(self.filename) # MS needs full path name
                command = ['C:\\Program Files\\Microsoft Security Client\\MpCmdRun.exe',
                           '-Scan', '-ScanType', '3', '-File',  absfile]
                p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                while(True):
                        retcode = p.poll() #returns None while subprocess is running
                        m = re.search('found 1 threats', p.stdout.readline())
                        if m: return True
                        if(retcode is not None):
                                break
                return False                                

###
# McAfee uvscan
#

class McAfeeScanner(AVscanner):
        def __init__(self, batchSize, fuzzfolder, initialOffset, filename):
                AVscanner.__init__(self, batchSize=batchSize, fuzzfolder=fuzzfolder, initialOffset=initialOffset, filename=filename)

        ###
        # parses the output of the scanner
        # defines the regexp to discern detected and undetected
        #
                
        def parse(self):        
                for i in range(self.currentOffset, self.nextOffset):
                        self.rawResults[i] = True 
                for line in self.scannerOutput:
                        m = re.search('tmpfile_(\w{8}) ... Found', line)
                        if m: 
                                self.rawResults[int(m.group(1), 16)] = False 
        ###
        # invokes the scanner and stores output in self.scannerOutput        
        # tests multiple files 
        # 
                
        def scan(self):
                command = ['uvscan', self.fuzzfolder]
                p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                self.scannerOutput = []
                while(True):
                        retcode = p.poll() #returns None while subprocess is running
                        self.scannerOutput.append(p.stdout.readline())        
                        if(retcode is not None):
                                break
        ###
        # invokes the scanner and stores output in self.scannerOutput        
        # tests just one signle file 
        # 

        def ismalicious(self):
                command = ['uvscan', self.filename]
                p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                while(True):
                        retcode = p.poll() #returns None while subprocess is running
                        m = re.search(' ... Found', p.stdout.readline())
                        if m: return True
                        if(retcode is not None):
                                break
                return False                                

###
# main routine
#

def main():
        # using optparse for compatibility with Python 2.6 (still seems to be used a lot, in Cygwin for example)
        usage = "usage: %prog [options] scanner_type sample_file\n" \
                "       scanner_type := {mcafee|ms}"
        parser = OptionParser(usage=usage)
        parser.add_option("-b", "--batchsize", dest="batchsize",
                  help="fuzzed batch size (number of fuzzed samples scanned at once)", type="int", default=1000)
        parser.add_option("-o", "--offset", dest="offset",
                  help="offset from which the file will be scanned", type="int", default=0x1000)
        parser.add_option("-t", "--tmpdir", dest="tmpdir",
                  help="temporary directory where the fuzzed file batch will be stored", default="fuzz")
        parser.add_option("-n", "--no-hashtest", dest="hashtest", action="store_false", default=True,
                  help="perform the test of using a file hash comparison signature and abort if yes")
        
        (options, args) = parser.parse_args()
        if len(args) != 2:
                parser.print_help()
                sys.exit(1)
        if args[0] == "ms":
                scanner = MSScanner(batchSize=options.batchsize, fuzzfolder=options.tmpdir, initialOffset=options.offset, filename=args[1])
        elif args[0] == "mcafee":
                scanner = McAfeeScanner(batchSize=options.batchsize, fuzzfolder=options.tmpdir, initialOffset=options.offset, filename=args[1])
        else:
                sys.stderr.write("%s: no such scanner type is supported\n" % args[0])
                parser.print_help()
                sys.exit(2)
        
        if not scanner.ismalicious():
                sys.stderr.write("This file does not seem to be flagged, aborting\n")
                sys.exit(3)

        if options.hashtest == True:
                if not scanner.ishash():
                        sys.stderr.write("The scanner seems to be doing a simple hash check, aborting\n")
                        sys.exit(4)
                
        while not scanner.last:
                results = scanner.getNext()
                for r in results.keys():
                        print "[*] found string, len: %d" % results[r]['length']
                        print hexdump(r, results[r]['text']) + "\n"
        scanner.cleanTmp()

if __name__ == '__main__':
    main()
