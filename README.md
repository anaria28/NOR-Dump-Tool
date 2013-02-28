
     NOR Dump Tool

 Open source project aimed to help to validate PS3 NOR dumps
 !! This code is NOT able to give you a 100%% validation status !!
 It's anyway better to do additional checking by your own,
 unless the code of this tool is fully validated by experts!!!

  All credits go to ps3devwiki and its contributors.
  
 I have no pretension for it but I'd like from anyone who enjoy it,
 to keep it as an opensource project,
 if this code or any part of it is used for another application,
 I ask you to make it public as well,
 if you like this code and write some changes please share it with everyone.


    Usage: ./NORDumpTool NorFile.bin (Options)
        --help                 : Display this help.
        -v                     : Verbose for debugging purposes
                                 A lot of data may output especially if the dump is defective
        -P                     : Give percentage of bytes
        -G                     : Check PS3 Generic information
        -C                     : Check and display perconsole information
        -f                     : Check areas filled with '00' or 'FF'
        -F                     : Check Firmware information (ros0/1 + trvk)
        -N                     : Check areas containing data in opposition to -F option
        -R                     : Check simple repetition of bytes due to stuck line
        -S FolderName          : Split some NOR section to folder 'FolderName'
        -M Start Size          : Run MD5 sum on file from 'Start' for 'Size' long
        -E FileName Start Size : Extract specific NOR Section from 'Start' for 'Size' long
        -D Start Size H/A      : Display a specific NOR Section 
                                from 'Start' for 'Size' long, use H or A for HEX or ASCII

    By default -P -G -C -f -F -N and -R will be applied if no option is given

Examples:
 - Display Usage list:
 ./NORDumpTool
    or
 ./NORDumpTool --help

 - Check a dump:
 ./NORDumpTool dumpfilename.bin

 - Split the dump into separate files (like asecure_loader, eEID and so on.) to a folder. No checking done here! it just extract the binaries
 ./NORDumpTool dumpfilename.bin -S FolderNameWhereToStoreFiles
