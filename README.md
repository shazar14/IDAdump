## IDAdump
The purpose of this script is to verify the presence of a PE file in an IDA DB,
correctly calculate the size from the PE header, and write the file to disk

### Note
This script was written on Carbon Black time.  Thank you for the time and 
support to write something I've been meaning to write for some time

## Usage
Open file in IDA pro. Point cursor at the `M (or 0x4D)` in the IDA DB and run this script

![Point to M](/images/usage1.png?raw=true "Step 1")

Select File->Script File... and select idadump_mz.py

For testing I have provided binaries that contain an embedded binary inline as well as binary in the .rsrc section.
Here are the results of both being dumped to disk

![Output](/images/usage2.png?raw=true "Result 1")

![Output](/images/usage3.png?raw=true "Result 2")
