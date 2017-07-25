'''
MIT License

Copyright (c) 2017 Eric Merritt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

============

Note: This script was written on Carbon Black time.  Thank you for the time and 
support to write something I've been meaning to write for some time.

The purpose of this script is to verify the presence of a PE file in an IDA DB,
correctly calculate the size from the PE header, and write the file to disk.

Usage
============
Point cursor at the `M` (or 0x4D) in an IDA DB and run this script
'''


import sys
import hashlib

# Used to parse PE header. Download from: http://code.google.com/p/pefile/
# or `pip install pefile`
try:
	import pefile 
except ImportError:
	print "[-] Pefile module required.  Install from http://code.google.com/p/pefile/ or `pip install pefile`"
	sys.exit(1)

try:
	import idc
except ImportError:
	print "[-] This script must be ran in conjuction with IDA"
	sys.exit(1)


# Verify the MZ header before proceeding
def verify_mz_magic(pointer):
	dos_hdr = GetManyBytes((pointer + 78), 33, False)
	mz_hdr = idc.Word(pointer)

	if mz_hdr == pefile.IMAGE_DOS_SIGNATURE and dos_hdr == "This program cannot be run in DOS":
		return True
	else:
		return False


# Verify the PE header and get the file size
def getSize_FromPE(pointer):
	header = GetManyBytes(pointer, 0x400, False)

	try:
		pe = pefile.PE(data=header)
	except Exception as e:
		print '[-] Failed to read header data: %s' % e
		return 0

	size = pe.OPTIONAL_HEADER.SizeOfHeaders

	for section in pe.sections:
		size = size + section.SizeOfRawData

	return size

# Read the number of bytes from the selected byte
def getData(pointer, size):
	data = GetManyBytes(pointer, size, False)
	return data


def hashData(data):
	md5 = hashlib.md5(data).hexdigest()
	return md5 

# Modified from https://gist.github.com/rji/b38c7238128edf53a181
def sha256Hash(data, block_size=65536):
    sha256 = hashlib.sha256()
    counter = 0
    while counter < len(data):
    	sha256.update(data[counter:block_size])
    	counter = counter + block_size
    return sha256.hexdigest()

# Write out the carved file to disk
def writeData(data, filename):
	try:
		with open(filename, 'wb') as f:
			f.write(data)
	except Exception as e:
		print '[-] Failed to write data: %s' %e
		return False
	return True


def main():
	print '\n'

	# Get user selected address
	select_pointer = ScreenEA()

	if select_pointer is None:
		print "[-] No Address selected"
		return

	print "[+] Checking for valid MZ header @ 0x%X..." % select_pointer,

	# Verify the header is PECOFF format
	if verify_mz_magic(select_pointer):
		print "Valid"
	else:
		print "\n[-] Invalid MZ header"
		return

	# Manually calculate the filesize from section and header sizes
	print '[+] Calculating file size...',
	file_size = getSize_FromPE(select_pointer)

	if file_size != 0:
		print '0x%X bytes' % file_size
	else:
		print '\n[-] Error calculating file size'
		return

	# Read in the calculated size of the file
	carved_file = GetManyBytes(select_pointer, file_size, False)

	# Hash data
	try:		
		print '[+] MD5: ',
		print hashData(carved_file).upper()
		print '[+] SHA2: ',
		print sha256Hash(carved_file).upper()
	except:
		print '\n[-] Failed to hash data\n'

	print '[+] Writing file to disk as...',

	# Generate a name with a number in case there are multiple files to carve
	analyzed_filename = idc.GetInputFile()
	
	# Generate a filename based on the file being analyzed and the address of the carved file
	out_file = '%s_%X_carved.exe' % (analyzed_filename.split('.')[0], select_pointer)
	if not writeData(carved_file, out_file):
		print '\n[-] Error writing carved file to disk'
		return
	else:
		print '%s' % out_file
		


if __name__ == '__main__':
    main()