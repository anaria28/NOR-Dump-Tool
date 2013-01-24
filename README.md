
     NOR Dump Tool

Open source project aimed to help to validate PS3 NOR dumps
At the moment (January 2013) the code is probably able
to give you a validation status of roughly 90%!?
It's anyway better to do additional checking by your own,
unless the code of this tool is fully validated by experts!!!

I have no pretension for it but I'd like from anyone who enjoy it,
 to keep it as an opensource project,
 if this code or any part of it is used for another application,
 I ask you to make it public as well,
 if you like this code and write some changes please share it with everyone.


Usage: ./NORDumpTool NorFile.bin (Options)
Option: -P : Give percentage of bytes
Option: -G : Check PS3 Generic information
Option: -C : Check and display perconsole information
Option: -F : Check areas filled with '00' or 'FF'
Option: -S FolderName : Split some NOR section to folder 'FolderName'
Option: -M Start Size : Run MD5 sum on file from 'Start' for 'Size' long
Option: -E FileName Start Size : Extract specific NOR Section from 'Start' for 'Size' long
Option: -D Start Size H/A : Display a specific NOR Section from 'Start' for 'Size' long,
                use H or A for Hexa or ASCII
By default -P -G -C and -F will be applied if no option is given

Examples:
 - Display Usage list:
 ./NORDumpTool

 - Check a dump:
 ./NORDumpTool dumpfilename.bin

 - Split the dump into separate files to a folder like asecure_loader, eEID and so on. No checking done here! it just extract the binaries
 ./NORDumpTool dumpfilename.bin -S FolderNameWhereToStoreFiles
