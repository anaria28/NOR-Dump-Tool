
// Knowledge and information sources : ps3devwiki.com | ps3hax.net | your friend google
// Thanks to all people sharing their findings and knowledge!
//
// Aim of this code:
// - Check as much as possible a NOR dump in order to validate it
// - Run some statistics on the dump (% of '00' 'FF' ...)
// - Extract some specific console information (S/N, MAC, and so on)
//
// Versions :
// 0.9.x Changed text display fail red to bold red
//       Moved to Code::Blocks + MingW32
//       Added Verbose option mainly for debugging
//       Added Byte reversing routine
//       Added pattern repetition
// 0.9.6 Increased checking of area filled with unique byte(s)
//       Added percentage indicator
//       Added global status
//       Added Fixed of some part of the code & cleaning from an0nym0u5
//       Changed MD5 function, the first one was only valid if done on a full file not on inner sections.
//       Added report for trvk and ros' files MD5
//       move part of the definitons in PS3Data.h
// 0.9.5 Increased portability to Windows via MinGW32
// 0.9.4 Fixed stupid mistake in ReadSection() (Thx @Sarah1331)
// 0.9.3 Added checking of area filled with unique byte(s) e.g. in flash format: 0x210 -> 0x3FF : full of FF
// 0.9.2 memory allocation fix (Thx @judges) in CheckPerConsoleData() + fixed wrong English (mixed French...) in main()
// 0.9.1 Added -D option to display a specific section in HEX or ASCII
// 0.9.0 First public release

//Generic includes for POSIX platforms
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/md5.h>

//Includes specific to the project.

#include "PS3Data.h"

enum msgType
{
    WARNING  = -2,
    FAILURE,
    GOOD,
    VERBOSE,
    INFO
};

#ifdef __MINGW32__ || _WIN32 || _WIN64
// for windows
#define Win32 0
#define MKDIR(x,y) mkdir(x)
#include <windows.h>
static CONSOLE_SCREEN_BUFFER_INFO ConsoleDefault;

void GetTextDefault()
{
    GetConsoleScreenBufferInfo (GetStdHandle(STD_OUTPUT_HANDLE), &ConsoleDefault);
}
void SetTextNONE    ()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), ConsoleDefault.wAttributes );

}
void SetTextBOLD    ()
{
    CONSOLE_SCREEN_BUFFER_INFO ConsoleAttribute;
    GetConsoleScreenBufferInfo (GetStdHandle(STD_OUTPUT_HANDLE), &ConsoleAttribute);
    SetConsoleTextAttribute (GetStdHandle(STD_OUTPUT_HANDLE), ConsoleAttribute.wAttributes | FOREGROUND_INTENSITY );
}
void SetTextRED     ()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED);
}
void SetTextGREEN   ()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN);
}
void SetTextYELLOW  ()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN);
}
void SetTextBLUE    ()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE);
}
void SetTextMAGENTA ()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_BLUE);
}
void SetTextCYAN    ()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_BLUE);
}
void SetTextWHITE   ()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}
#else
// for the real world
#define MKDIR(x,y) mkdir(x,y)
#define Win32 -1
void SetTextNONE    ()
{
    printf ("\e[m");
}
void SetTextBOLD    ()
{
    printf ("\e[1m");
}
void SetTextRED     ()
{
    printf ("\e[31m");
}
void SetTextGREEN   ()
{
    printf ("\e[32m");
}
void SetTextYELLOW  ()
{
    printf ("\e[33m");
}
void SetTextBLUE    ()
{
    printf ("\e[34m");
}
void SetTextMAGENTA ()
{
    printf ("\e[35m");
}
void SetTextCYAN    ()
{
    printf ("\e[36m");
}
void SetTextWHITE   ()
{
    printf ("\e[37m");
}
#endif

#define NOR_DUMP_TOOL_VERSION   "0.9.x"

#define TYPE_HEX                0x00
#define TYPE_ASCII              0x01
#define DISPLAY_ALWAYS          0x02
#define DISPLAY_FAIL            0x04
#define DISPLAY_GOOD            0x08

#define NB_OPTIONS              11

#define OPTION_SPLIT            0x01
#define OPTION_MD5              0x02
#define OPTION_EXTRACT          0x04
#define OPTION_STATS            0x08
#define OPTION_CHECK_GENERIC    0x10
#define OPTION_CHECK_PERPS3     0x20
#define OPTION_DISPLAY_AREA     0x40
#define OPTION_CHECK_FILLED     0x80
#define OPTION_CHECK_NOT_ZERO   0x100
#define OPTION_CHECK_PER_FW     0x200
#define OPTION_CHECK_REPETITION 0x400

#define DATA_BUFFER_SIZE        0x40

#define NOT_FOUND               -1
#define NOT_BROKEN              -2
#define IS_BROKEN               -3

static uint8_t Verbose          = -1;
static uint8_t Reverse          = -1;
static char    *NORFileName     = "NORDumpFileName.bin";

struct Options
{
    char       *Name;
    int        Type;
    uint32_t   Start;
    uint32_t   Size;
};

enum ReportChecking
{
    ReportMD5 = 0,
    ReportExtraction,
    ReportStatistics,
    ReportGenericData,
    ReportPerConsoleData,
    ReportFilledArea,
    ReportNotZero,
    ReportPerFW,
    ReportRepetition,
    NBToReport
};

struct Reporting
{
    uint8_t ReportNumber;
    char *ReportName;
    char *ReportMsg;
};

char *bufferByteSwap (char *BufferToSwap, uint8_t StringType, uint32_t BufferSize)
{
    if (strlen(BufferToSwap)==0)
        return ;

    char *Buffer;
    Buffer = malloc(3);
    uint32_t Cursor = 0;
    uint8_t SwapSize = 1;

    if (!Verbose)
    {
        SetTextCYAN ();
        printf ("Swapping bytes in string ongoing...\n");
        SetTextNONE ();
    }

    if (StringType == TYPE_HEX)
    {
        SwapSize = 2;
    }

    else if (StringType == TYPE_ASCII)
    {
        SwapSize = 1;
    }

    for (Cursor=0; Cursor<BufferSize-SwapSize; Cursor+=SwapSize*2)
    {
        memcpy  (Buffer, BufferToSwap+Cursor, SwapSize);
        memmove (BufferToSwap+Cursor, BufferToSwap+Cursor+SwapSize, SwapSize);
        memcpy  (BufferToSwap+Cursor+SwapSize, Buffer, SwapSize);
    }

    free (Buffer);
    return BufferToSwap;
}

void printStatus(const char *Text, int8_t TextType)
{

    switch (TextType)
    {
    case FAILURE:
    {
        SetTextRED ();
        SetTextBOLD ();
        printf ("%s",Text);
        break;
    }
    case GOOD:
    {
        SetTextGREEN ();
        printf ("%s",Text);
        break;
    }
    case WARNING:
    {
        SetTextYELLOW ();
        printf ("%s",Text);
        break;
    }
    case VERBOSE:
    {
        SetTextCYAN ();
        printf ("%s",Text);
        break;
    }
    default:
    {
        break;
    }
    }
    SetTextNONE ();
}

void MD5SumFileSection( FILE *FileToRead, uint32_t Position, uint32_t Size, uint8_t *Sum)
{
    char *Buffer;
    Buffer = malloc(Size+1);

    fseek (FileToRead, Position, SEEK_SET);
    fread (Buffer, Size, 1, FileToRead);

    if (!Reverse)
        bufferByteSwap(Buffer, TYPE_ASCII, Size);

    MD5 (Buffer, Size, Sum);
    free (Buffer);
}

void printMD5 (uint8_t MD5result[MD5_DIGEST_LENGTH])
{
    uint8_t Cursor;
    for(Cursor = 0; Cursor < MD5_DIGEST_LENGTH; Cursor++)
        printf ("%02X",MD5result[Cursor]);
}

uint8_t CompareMD5(uint8_t MD5result[MD5_DIGEST_LENGTH], char *MD5Compare)
{
    uint8_t Cursor;
    uint8_t Status=EXIT_SUCCESS;
    char Buffer[MD5_DIGEST_LENGTH*2+1] = {0};

    for(Cursor = 0; Cursor < MD5_DIGEST_LENGTH; Cursor++)
        sprintf (Buffer,"%s%02X",Buffer,MD5result[Cursor]);

    for(Cursor = 0; Cursor < MD5_DIGEST_LENGTH*2+1; Cursor++)
    {
        if (Buffer[Cursor]==MD5Compare[Cursor])
            Status |= EXIT_SUCCESS;
        else
            Status |= EXIT_FAILURE;
    }

    return Status;
}

uint8_t ExtractSection(char* SectionName, FILE *FileToRead, uint32_t Position, uint32_t Size)
{
    uint32_t Cursor;
    char *Buffer;
    FILE *BinaryFile;

    BinaryFile = fopen(SectionName, "wb");
    if (!BinaryFile)
    {
        printf ("Failed to open %s\n", SectionName);
        return EXIT_FAILURE;
    }

    fseek(FileToRead, Position, SEEK_SET);

    if((Buffer = malloc(Size + 1)))
        fread(Buffer, Size, 1, FileToRead);

    if (!Reverse)
        bufferByteSwap(Buffer, TYPE_ASCII, Size);

    for (Cursor=0; Cursor<Size; Cursor++)
        fputc(Buffer[Cursor], BinaryFile);

    printf ("Extraction done for %s\n", SectionName);
    fclose(BinaryFile);
    free (Buffer);
    return EXIT_SUCCESS;
}

uint8_t Statistics(FILE *FileToRead)
{
    // Calculate some statistics on bytes percentages
    uint8_t Status = EXIT_SUCCESS;
    uint32_t Cursor;
    uint16_t Counter;
    uint32_t CountOthers = 0;
    uint32_t CountByte[0xFF+1];

    char msg_low[]  = "Too Low";
    char msg_high[] = "Too High";
    char msg_good[] = "Good";

    char *Status00     = NULL;
    char *StatusFF     = NULL;
    char *StatusOthers = NULL;

    uint8_t Fail00     = FAILURE;
    uint8_t FailFF     = FAILURE;
    uint8_t FailOthers = FAILURE;

    printf ("******************************\n");
    printf ("*         Statistics         *\n");
    printf ("******************************\n");

    fseek (FileToRead, 0, SEEK_SET);

    for (Counter=0x00; Counter<0xFF+1; Counter++)
        CountByte[Counter]=0;

    for (Cursor=0; Cursor<NOR_FILE_SIZE; Cursor++)
        CountByte[fgetc(FileToRead)]+=1;

    if (!Verbose)
    {
        SetTextCYAN ();
        printf ("\nVerbose Start\n");
        for (Counter=0x00; Counter<0xFF+1; Counter++)
            printf ("Bytes '%02X' found %7d times, %02.2f%%\n", Counter, CountByte[Counter], (double)CountByte[Counter]*100/(double)NOR_FILE_SIZE);
        printf ("Verbose End\n\n");
        SetTextNONE ();
    }

    for (Counter=0x01; Counter<0xFF; Counter++)
    {
        if (CountOthers<CountByte[Counter])
            CountOthers=CountByte[Counter];
    }

    if (CountByte[0x00]<MIN00)
    {
        Status00 = msg_low;
        Status   = EXIT_FAILURE;
    }
    else if (CountByte[0x00]>MAX00)
    {
        Status00 = msg_high;
        Status   = EXIT_FAILURE;
    }
    else
    {
        Status00 = msg_good;
        Fail00   = GOOD;
    }

    if (CountByte[0xFF]<MINFF)
    {
        StatusFF = msg_low;
        Status   = EXIT_FAILURE;
    }
    else if (CountByte[0xFF]>MAXFF)
    {
        StatusFF = msg_high;
        Status   = EXIT_FAILURE;
    }
    else
    {
        StatusFF = msg_good;
        FailFF   = GOOD;
    }

    if (CountOthers>MAXOTHERS)
    {
        StatusOthers = msg_high;
        Status       = EXIT_FAILURE;
    }
    else
    {
        StatusOthers = msg_good;
        FailOthers   = GOOD;
    }

    printf ("Bytes '00' found %d times, %2.2f%% "         , CountByte[0x00], (double)CountByte[0x00]*100/(double)NOR_FILE_SIZE);
    printStatus (Status00, Fail00);
    printf ("\n");
    printf ("Bytes 'FF' found %d times, %2.2f%% "         , CountByte[0xFF], (double)CountByte[0xFF]*100/(double)NOR_FILE_SIZE);
    printStatus (StatusFF, FailFF);
    printf ("\n");
    printf ("Other bytes found %d times maximum, %2.2f%% ", CountOthers    , (double)CountOthers    *100/(double)NOR_FILE_SIZE);
    printStatus (StatusOthers, FailOthers);
    printf ("\n");

    return Status;
}

void GetSection(FILE *FileToRead, uint32_t Position, uint8_t Size, uint8_t DisplayType, char *section_data)
{
    // Reads area from file and put it in section_data pointer
    // In Parameters:
    //  FILE *FileToRead     : File to read from
    //   uint32_t Position   : Offset to read from
    //   uint8_t Size        : Length of data to read
    //   uint8_t DisplayType : Print out in HEX or ASCII
    //   char *section_data  : Data to return

    uint16_t Cursor;
    *section_data=NULL;

    fseek(FileToRead, Position, SEEK_SET);

    if (((DisplayType)&(1<<0))==TYPE_HEX)
    {
        if (!Verbose)
        {
            SetTextCYAN ();
            printf ("TYPE_HEX ", Position, section_data);
            SetTextNONE ();
        }
        for (Cursor=0; Cursor<Size; Cursor++)
        {
            sprintf (section_data, "%s%02X", section_data, fgetc(FileToRead));
        }
    }
    else if (((DisplayType)&(1<<0))==TYPE_ASCII)
    {
        if (!Verbose)
        {
            SetTextCYAN ();
            printf ("TYPE_ASCII ", Position, section_data);
            SetTextNONE ();
        }
        for (Cursor=0; Cursor<Size; Cursor++)
        {
            sprintf (section_data, "%s%c", section_data, fgetc(FileToRead));
        }
        //fread(section_data, Size, 1, FileToRead);
        //section_data[Size]=NULL;
    }

    if (!Reverse)
        bufferByteSwap(section_data, (DisplayType)&(1<<0), strlen(section_data));

    if (!Verbose)
    {
        SetTextCYAN ();
        printf ("GetSection: at '%06X' read '%s' \n", Position, section_data);
        SetTextNONE ();
    }
}

uint8_t ReadSection(char *SectionName, FILE *FileToRead, uint32_t Position, uint8_t Size, uint8_t DisplayType, uint8_t CheckFlag, char *CheckPattern)
{
    // Reads area from file and check it with a given pattern
    // In Parameters:
    //  char *SectionName   : Name to print out for the section
    //  FILE *FileToRead    : File to read from
    //  uint32_t Position   : Offset to read from
    //  uint8_t Size        : Length of data to read
    //  uint8_t DisplayType : Print out in HEX or ASCII, always or only if fail to check
    //  uint8_t CheckFlag   : Check a given pattern
    //  char *CheckPattern  : Pattern to check, has to be the same size of data read

    uint8_t Cursor;
    uint8_t Status=EXIT_SUCCESS;
    char DisplaySection[0x100]= {0};

    fseek(FileToRead, Position, SEEK_SET);

    for (Cursor=0; Cursor<Size; Cursor++)
    {
        if (((DisplayType)&(1<<0))==TYPE_HEX)
            sprintf (DisplaySection, "%s%02X", DisplaySection,fgetc(FileToRead));

        else if (((DisplayType)&(1<<0))==TYPE_ASCII)
            sprintf (DisplaySection, "%s%c", DisplaySection,fgetc(FileToRead));
    }

    if (!Verbose)
    {
        //printf ("\nVerbose Start\n");
        SetTextCYAN ();
        printf ("ReadSection: at '%06X' read '%s' \n", Position, DisplaySection);
        SetTextNONE ();
        //printf ("Verbose End\n\n");
    }
    if (!Reverse)
        bufferByteSwap(DisplaySection, (DisplayType)&(1<<0), strlen(DisplaySection));

    if (((DisplayType)&(1<<1))==DISPLAY_ALWAYS)
    {
        printf ("Section: %s: read %s", SectionName, DisplaySection);
        printf("\n");
    }

    if (CheckFlag)
    {
        for (Cursor=0; Cursor<Size; Cursor++)  // '*' is use to filter hex ASCII: 0x2A
        {
            if (((DisplayType)&(1<<0))==TYPE_ASCII)
            {
                if ((DisplaySection[Cursor]!=CheckPattern[Cursor])&&(CheckPattern[Cursor]!=0x2A))
                {
                    Status=EXIT_FAILURE;
                    if (((DisplayType)&(1<<2))==DISPLAY_FAIL)
                    {
                        printf ("Section: %s: read '%s' !   mismatch pattern '%s' ! "
                                , SectionName
                                , DisplaySection
                                , CheckPattern);
                        printStatus ("FAIL", FAILURE);
                        printf("\n");
                    }
                    // else if (((DisplayType)&(1<<1))==DISPLAY_ALWAYS) {
                    // printf (" !   mismatch pattern '\e[33m%s\e[m' ! \e[1m\e[31mFAIL\e[m\n", CheckPattern);
                    // }

                    return Status;
                }
                else
                {
                    if (((DisplayType)&(1<<3))==DISPLAY_GOOD)
                    {
                        printf ("Section: %s: read '%s' !   match pattern '%s' ! "
                                , SectionName
                                , DisplaySection
                                , CheckPattern);
                        printStatus ("GOOD", GOOD);
                        printf("\n");
                    }
                    // else if (((DisplayType)&(1<<1))==DISPLAY_ALWAYS) {
                    // printf (" ! \e[32mGOOD\e[m\n");
                    // }
                }
            }
            else if (((DisplayType)&(1<<0))==TYPE_HEX)
            {
                if (((DisplaySection[Cursor*2]!=CheckPattern[Cursor*2])&&(CheckPattern[Cursor*2]!=0x2A))||((DisplaySection[Cursor*2+1]!=CheckPattern[Cursor*2+1])&&(CheckPattern[Cursor*2+1]!=0x2A)))
                {
                    Status=EXIT_FAILURE;
                    if (((DisplayType)&(1<<2))==DISPLAY_FAIL)
                    {
                        printf ("Section: %s: read '%s' !   mismatch pattern '%s' ! "
                                , SectionName
                                , DisplaySection
                                , CheckPattern);
                        printStatus ("FAIL", FAILURE);
                        printf("\n");
                    }
                    // else if (((DisplayType)&(1<<1))==DISPLAY_ALWAYS) {
                    // printf (" !   mismatch pattern '\e[33m%s\e[m' ! \e[1m\e[31mFAIL\e[m\n", CheckPattern);
                    // }
                    return Status;
                }
                else
                {
                    if (((DisplayType)&(1<<3))==DISPLAY_GOOD)
                    {
                        printf ("Section: %s: read '%s' !   match pattern '%s' ! "
                                , SectionName
                                , DisplaySection
                                , CheckPattern);
                        printStatus ("GOOD", GOOD);
                        printf("\n");
                    }
                    // else if (((DisplayType)&(1<<1))==DISPLAY_ALWAYS) {
                    // printf (" ! \e[32mGOOD\e[m\n");
                    // }
                }
            }
        }
    }
    //else {
    //    if (((DisplayType)&(1<<1))==DISPLAY_ALWAYS)
    //printf ("\n");
    //}
    return Status;
}

uint8_t CheckRepetition(FILE *FileToRead, char *LineStuck)
{
    uint32_t Cursor;
    uint32_t AddressIndex;
    char *Buffer;
    Buffer = malloc(0x08 + 1);
    uint8_t Status=EXIT_SUCCESS;

    printf ("******************************\n");
    printf ("*      Data Repetition       *\n");
    printf ("******************************\n");

    GetSection (FileToRead, SectionTOC[FlashStart].Offset+0x14, 0x04, TYPE_HEX, Buffer);

    Cursor = 0;
    while (AddressLine[Cursor].Address<NOR_FILE_SIZE)
        Cursor+=1;

    while (Cursor>2)
    {
        Cursor--;
        AddressIndex = AddressLine[Cursor].Address;
        //while (AddressIndex<NOR_FILE_SIZE)
        //{
            if (!Verbose)
            {
                SetTextCYAN ();
                printf ("- item '%d', checking repetition at Address '%08X'\n", Cursor, SectionTOC[FlashStart].Offset+AddressIndex+0x14);
                SetTextNONE ();
            }
            if (ReadSection("Repetition", FileToRead, SectionTOC[FlashStart].Offset+AddressIndex+0x14, 0x04, TYPE_HEX, 1, Buffer)==EXIT_SUCCESS)
            {
                SetTextRED();
                SetTextBOLD();
                printf("Repetition found on Address '%08X' meaning line '%s' is stuck\n", AddressLine[Cursor].Address, AddressLine[Cursor].LineName);
                SetTextNONE();
                strcpy(LineStuck,AddressLine[Cursor].LineName);
                Status=EXIT_FAILURE;
                break;
            }
            else
            {
                printf ("No repetition found on Address '%08X' ! ", AddressIndex);
                printStatus("GOOD",GOOD);
                printf ("\n");
            }
            //AddressIndex += AddressLine[Cursor].Address;
        //}
    }

    free (Buffer);
    return Status;
}

uint8_t CheckGenericData(FILE *FileToRead, uint32_t *PercentCheck)
{
    int Cursor=0;
    uint8_t Status=EXIT_SUCCESS;
    uint32_t SizedCheck=0;
    struct Sections SectionGenericData[] =
    {
        {"Flash Magic Number     ", SectionTOC[FlashStart].Offset+0x10    , 0x10, TYPE_HEX  +DISPLAY_FAIL, 1, "000000000FACE0FF00000000DEADBEEF"},
        {"Flash Region Length    ", SectionTOC[FlashStart].Offset+0x20    , 0x10, TYPE_HEX  +DISPLAY_FAIL, 1, "00000000000000000000000000007800"},
        {"Flash Format Type      ", SectionTOC[FlashFormat].Offset        , 0x10, TYPE_HEX  +DISPLAY_FAIL, 1, "49464900000000010000000200000000"},
        {"FlashRegion Unkown     ", SectionTOC[FlashRegion].Offset        , 0x04, TYPE_HEX  +DISPLAY_FAIL, 1, "00000001"},
        {"FlashRegion Entry Count", SectionTOC[FlashRegion].Offset+0x0004 , 0x04, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000B"},
        {"FlashRegion Length     ", SectionTOC[FlashRegion].Offset+0x0008 , 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000EFFC00"},
        {"FlashRegion  1 offset  ", SectionTOC[FlashRegion].Offset+0x0010 , 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000000400"},
        {"FlashRegion  1 length  ", SectionTOC[FlashRegion].Offset+0x0018 , 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "000000000002E800"},
        {"FlashRegion  1 name    ", SectionTOC[FlashRegion].Offset+0x0020 , 0x0E, TYPE_ASCII+DISPLAY_FAIL, 1, "asecure_loader"},
        {"FlashRegion  1 NULL    ", SectionTOC[FlashRegion].Offset+0x002E , 0x12, TYPE_HEX  +DISPLAY_FAIL, 1, "000000000000000000000000000000000000"},
        {"FlashRegion  2 offset  ", SectionTOC[FlashRegion].Offset+0x0040 , 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "000000000002EC00"},
        {"FlashRegion  2 length  ", SectionTOC[FlashRegion].Offset+0x0048 , 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000010000"},
        {"FlashRegion  2 name    ", SectionTOC[FlashRegion].Offset+0x0050 , 0x04, TYPE_ASCII+DISPLAY_FAIL, 1, "eEID"},
        {"FlashRegion  2 NULL    ", SectionTOC[FlashRegion].Offset+0x0054 , 0x1C, TYPE_HEX  +DISPLAY_FAIL, 1, "00000000000000000000000000000000000000000000000000000000"},
        {"FlashRegion  3 offset  ", SectionTOC[FlashRegion].Offset+0x0070 , 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "000000000003EC00"},
        {"FlashRegion  3 length  ", SectionTOC[FlashRegion].Offset+0x0078 , 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000000800"},
        {"FlashRegion  3 name    ", SectionTOC[FlashRegion].Offset+0x0080 , 0x04, TYPE_ASCII+DISPLAY_FAIL, 1, "cISD"},
        {"FlashRegion  3 NULL    ", SectionTOC[FlashRegion].Offset+0x0084 , 0x1C, TYPE_HEX  +DISPLAY_FAIL, 1, "00000000000000000000000000000000000000000000000000000000"},
        {"FlashRegion  4 offset  ", SectionTOC[FlashRegion].Offset+0x00A0 , 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "000000000003F400"},
        {"FlashRegion  4 length  ", SectionTOC[FlashRegion].Offset+0x00A8 , 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000000800"},
        {"FlashRegion  4 name    ", SectionTOC[FlashRegion].Offset+0x00B0 , 0x04, TYPE_ASCII+DISPLAY_FAIL, 1, "cCSD"},
        {"FlashRegion  4 NULL    ", SectionTOC[FlashRegion].Offset+0x00B4 , 0x1C, TYPE_HEX  +DISPLAY_FAIL, 1, "00000000000000000000000000000000000000000000000000000000"},
        {"FlashRegion  5 offset  ", SectionTOC[FlashRegion].Offset+0x00D0 , 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "000000000003FC00"},
        {"FlashRegion  5 length  ", SectionTOC[FlashRegion].Offset+0x00D8 , 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000020000"},
        // http://www.ps3devwiki.com/wiki/Flash:Revoke_Program#trvk_prg0
        {"FlashRegion  5 name    ", SectionTOC[FlashRegion].Offset+0x00E0 , 0x0A, TYPE_ASCII+DISPLAY_FAIL, 1, "trvk_prg0\0"},
        {"FlashRegion  5 NULL    ", SectionTOC[FlashRegion].Offset+0x00EA , 0x16, TYPE_HEX  +DISPLAY_FAIL, 1, "000000000000000000000000000000000000000000000"},
        {"FlashRegion  6 offset  ", SectionTOC[FlashRegion].Offset+0x0100 , 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "000000000005FC00"},
        {"FlashRegion  6 length  ", SectionTOC[FlashRegion].Offset+0x0108 , 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000020000"},
        {"FlashRegion  6 name    ", SectionTOC[FlashRegion].Offset+0x0110 , 0x0A, TYPE_ASCII+DISPLAY_FAIL, 1, "trvk_prg1\0"},
        {"FlashRegion  6 NULL    ", SectionTOC[FlashRegion].Offset+0x011A , 0x16, TYPE_HEX  +DISPLAY_FAIL, 1, "000000000000000000000000000000000000000000000"},
        {"FlashRegion  7 offset  ", SectionTOC[FlashRegion].Offset+0x0130 , 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "000000000007FC00"},
        {"FlashRegion  7 length  ", SectionTOC[FlashRegion].Offset+0x0138 , 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000020000"},
        // http://www.ps3devwiki.com/wiki/Flash:Revoke_Package#trvk_pkg0
        {"FlashRegion  7 name    ", SectionTOC[FlashRegion].Offset+0x0140 , 0x0A, TYPE_ASCII+DISPLAY_FAIL, 1, "trvk_pkg0\0"},
        {"FlashRegion  7 NULL    ", SectionTOC[FlashRegion].Offset+0x014A , 0x16, TYPE_HEX  +DISPLAY_FAIL, 1, "000000000000000000000000000000000000000000000"},
        {"FlashRegion  8 offset  ", SectionTOC[FlashRegion].Offset+0x0160 , 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "000000000009FC00"},
        {"FlashRegion  8 length  ", SectionTOC[FlashRegion].Offset+0x0168 , 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000020000"},
        {"FlashRegion  8 name    ", SectionTOC[FlashRegion].Offset+0x0170 , 0x0A, TYPE_ASCII+DISPLAY_FAIL, 1, "trvk_pkg1\0"},
        {"FlashRegion  8 NULL    ", SectionTOC[FlashRegion].Offset+0x017A , 0x16, TYPE_HEX  +DISPLAY_FAIL, 1, "000000000000000000000000000000000000000000000"},
        {"FlashRegion  9 offset  ", SectionTOC[FlashRegion].Offset+0x0190 , 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "00000000000BFC00"},
        {"FlashRegion  9 length  ", SectionTOC[FlashRegion].Offset+0x0198 , 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000700000"},
        {"FlashRegion  9 name    ", SectionTOC[FlashRegion].Offset+0x01A0 , 0x04, TYPE_ASCII+DISPLAY_FAIL, 1, "ros0"},
        {"FlashRegion  9 NULL    ", SectionTOC[FlashRegion].Offset+0x01A4 , 0x1C, TYPE_HEX  +DISPLAY_FAIL, 1, "00000000000000000000000000000000000000000000000000000000"},
        {"FlashRegion 10 offset  ", SectionTOC[FlashRegion].Offset+0x01C0 , 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "00000000007BFC00"},
        {"FlashRegion 10 length  ", SectionTOC[FlashRegion].Offset+0x01C8 , 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000700000"},
        {"FlashRegion 10 name    ", SectionTOC[FlashRegion].Offset+0x01D0 , 0x04, TYPE_ASCII+DISPLAY_FAIL, 1, "ros1"},
        {"FlashRegion 10 NULL    ", SectionTOC[FlashRegion].Offset+0x01D4 , 0x1C, TYPE_HEX  +DISPLAY_FAIL, 1, "00000000000000000000000000000000000000000000000000000000"},
        {"FlashRegion 11 offset  ", SectionTOC[FlashRegion].Offset+0x01F0 , 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000EBFC00"},
        {"FlashRegion 11 length  ", SectionTOC[FlashRegion].Offset+0x01F8 , 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000040000"},
        {"FlashRegion 11 name    ", SectionTOC[FlashRegion].Offset+0x0200 , 0x06, TYPE_ASCII+DISPLAY_FAIL, 1, "cvtrm\0"},
        {"FlashRegion 11 NULL    ", SectionTOC[FlashRegion].Offset+0x0206 , 0x1A, TYPE_HEX  +DISPLAY_FAIL, 1, "00000000000000000000000000000000000000000000000000000"},
        {"metldr Start           ", SectionTOC[asecure_loader].Offset     , 0x04, TYPE_HEX  +DISPLAY_FAIL, 1, "00000001"},
        {"metldr Entry Count     ", SectionTOC[asecure_loader].Offset+0x04, 0x04, TYPE_HEX  +DISPLAY_FAIL, 1, "00000001"},
        {"metldr Region Length   ", SectionTOC[asecure_loader].Offset+0x08, 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "000000000002E800"},
        {"metldr File Offset     ", SectionTOC[asecure_loader].Offset+0x10, 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000000040"},
        //{"metldr File Length     ", SectionTOC[asecure_loader].Offset+0x18, 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "000000000000E8D0"},
        {"metldr file name       ", SectionTOC[asecure_loader].Offset+0x20, 0x06, TYPE_ASCII+DISPLAY_FAIL, 1, "metldr"},
        {"metldr blanks of name  ", SectionTOC[asecure_loader].Offset+0x26, 0x1A, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000000000000000000000000000000000000000000000"},
        {NULL, 0, 0, 0, 0, NULL}
    };

    printf ("******************************\n");
    printf ("*        Generic Data        *\n");
    printf ("******************************\n");
    while (SectionGenericData[Cursor].name!=NULL)
    {
        Status |= ReadSection(SectionGenericData[Cursor].name
                              , FileToRead
                              , SectionGenericData[Cursor].Offset
                              , SectionGenericData[Cursor].Size
                              , SectionGenericData[Cursor].DisplayType
                              , SectionGenericData[Cursor].Check
                              , SectionGenericData[Cursor].Pattern);
        SizedCheck += SectionGenericData[Cursor].Size;
        Cursor++;
    }

    *PercentCheck = SizedCheck;
    return Status;
}

uint8_t CheckPerConsoleData(FILE *FileToRead, uint32_t *PercentCheck)
{
    uint8_t Cursor      = 0;
    uint8_t SKUFound    = 0;
    uint8_t Status      = EXIT_SUCCESS;

    uint32_t SizedCheck = 0;

    char *Buffer          = malloc(DATA_BUFFER_SIZE+1);
    char *IDPSTargetID    = malloc(0x02+1);
    char *metldrOffset0   = malloc(0x08+1);
    char *metldrOffset1   = malloc(0x08+1);
    char *metldrSize      = malloc(0x08+1);
    char *bootldrOffset0  = malloc(0x08+1);
    char *bootldrOffset1  = malloc(0x08+1);
    char *bootldrSize     = malloc(0x08+1);
    char *pcn             = malloc(0x18+1);

    GetSection (FileToRead, SectionTOC[eEID].Offset+0x84, 0x0C, TYPE_HEX, pcn);
    GetSection (FileToRead, SectionTOC[asecure_loader].Offset+0x40, 0x04, TYPE_HEX, metldrSize);
    GetSection (FileToRead, SectionTOC[bootldr].Offset, 0x04, TYPE_HEX, bootldrSize);

    struct Sections SectionPerConsole[] =
    {
        {"mtldr revision     ", SectionTOC[asecure_loader].Offset+0x44   , 0x0C, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"mtldr binary size  ", SectionTOC[asecure_loader].Offset+0x50   , 0x04, TYPE_HEX  +DISPLAY_ALWAYS, 1, metldrSize},
        {"mtldr pcn          ", SectionTOC[asecure_loader].Offset+0x54   , 0x0C, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"EID0  -       IDPS ", SectionTOC[eEID].Offset+0x70             , 0x10, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"EID0 static        ", SectionTOC[eEID].Offset+0x80             , 0x04, TYPE_HEX  +DISPLAY_ALWAYS, 1, "0012000B"},
        {"EID0 pcn           ", SectionTOC[eEID].Offset+0x84             , 0x0C, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"EID3  - ckp_mgt_id ", SectionTOC[eEID].Offset+0x12A8           , 0x08, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"EID3 static        ", SectionTOC[eEID].Offset+0x12B0           , 0x04, TYPE_HEX  +DISPLAY_ALWAYS, 1, "000100D0"},
        {"EID3 pcn           ", SectionTOC[eEID].Offset+0x12B4           , 0x0C, TYPE_HEX  +DISPLAY_ALWAYS, 0, pcn},
        {"EID5  -       IDPS ", SectionTOC[eEID].Offset+0x13D0           , 0x10, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"EID5 static        ", SectionTOC[eEID].Offset+0x13E0           , 0x04, TYPE_HEX  +DISPLAY_ALWAYS, 1, "00120730"},
        {"EID5 pcn           ", SectionTOC[eEID].Offset+0x13E4           , 0x0C, TYPE_HEX  +DISPLAY_ALWAYS, 1, pcn},
        {"eEID Nb of Entries ", SectionTOC[eEID].Offset                  , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "00000006"},
        {"eEID Lentgh        ", SectionTOC[eEID].Offset+0x04             , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "00001DD0"},
        {"eEID Unknown/Blank ", SectionTOC[eEID].Offset+0x08             , 0x08, TYPE_HEX  +DISPLAY_FAIL  , 1, "0000000000000000"},
        {"eEID EID 0 Entry   ", SectionTOC[eEID].Offset+0x10             , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "00000070"},
        {"eEID EID 0 Length  ", SectionTOC[eEID].Offset+0x14             , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "00000860"},
        {"eEID EID 0         ", SectionTOC[eEID].Offset+0x18             , 0x08, TYPE_HEX  +DISPLAY_FAIL  , 1, "0000000000000000"},
        {"eEID EID 1 Entry   ", SectionTOC[eEID].Offset+0x20             , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "000008D0"},
        {"eEID EID 1 Length  ", SectionTOC[eEID].Offset+0x24             , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "000002A0"},
        {"eEID EID 1         ", SectionTOC[eEID].Offset+0x28             , 0x08, TYPE_HEX  +DISPLAY_FAIL  , 1, "0000000000000001"},
        {"eEID EID 2 Entry   ", SectionTOC[eEID].Offset+0x30             , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "00000B70"},
        {"eEID EID 2 Length  ", SectionTOC[eEID].Offset+0x34             , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "00000730"},
        {"eEID EID 2         ", SectionTOC[eEID].Offset+0x38             , 0x08, TYPE_HEX  +DISPLAY_FAIL  , 1, "0000000000000002"},
        {"eEID EID 3 Entry   ", SectionTOC[eEID].Offset+0x40             , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "000012A0"},
        {"eEID EID 3 Length  ", SectionTOC[eEID].Offset+0x44             , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "00000100"},
        {"eEID EID 3         ", SectionTOC[eEID].Offset+0x48             , 0x08, TYPE_HEX  +DISPLAY_FAIL  , 1, "0000000000000003"},
        {"eEID EID 4 Entry   ", SectionTOC[eEID].Offset+0x50             , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "000013A0"},
        {"eEID EID 4 Length  ", SectionTOC[eEID].Offset+0x54             , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "00000030"},
        {"eEID EID 4         ", SectionTOC[eEID].Offset+0x58             , 0x08, TYPE_HEX  +DISPLAY_FAIL  , 1, "0000000000000004"},
        {"eEID EID 5 Entry   ", SectionTOC[eEID].Offset+0x60             , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "000013D0"},
        {"eEID EID 5 Length  ", SectionTOC[eEID].Offset+0x64             , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "00000A00"},
        {"eEID EID 5         ", SectionTOC[eEID].Offset+0x68             , 0x08, TYPE_HEX  +DISPLAY_FAIL  , 1, "0000000000000005"},
        {"eEID EID 2 P Block ", SectionTOC[eEID].Offset+0x0B70           , 0x02, TYPE_HEX  +DISPLAY_FAIL  , 1, "0080"},
        {"eEID EID 2 S Block ", SectionTOC[eEID].Offset+0x0B72           , 0x02, TYPE_HEX  +DISPLAY_FAIL  , 1, "0690"},
        {"eEID EID 2 Blank   ", SectionTOC[eEID].Offset+0x0B74           , 0x1A, TYPE_HEX  +DISPLAY_FAIL  , 1, "00000000000000000000000000000000000000000000000000000000"},
        {"cISD Nb of Entries ", SectionTOC[cISD].Offset                  , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "00000003"}, //Number of entries (3 entries: cISD0, cISD1, and cISD2)
        {"cISD Lentgh        ", SectionTOC[cISD].Offset+0x04             , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "00000270"}, //cISD length (included header, file table, and all entries)
        {"cISD Unknown/Blank ", SectionTOC[cISD].Offset+0x08             , 0x08, TYPE_HEX  +DISPLAY_FAIL  , 1, "0000000000000000"}, //Unknown/Blank
        {"cISD cISD0 Entry   ", SectionTOC[cISD].Offset+0x10             , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "00000040"}, //ciSD0 Entry point
        {"cISD cISD0 Length  ", SectionTOC[cISD].Offset+0x14             , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "00000020"}, //ciSD0 Length
        {"cISD cISD0 NB      ", SectionTOC[cISD].Offset+0x18             , 0x08, TYPE_HEX  +DISPLAY_FAIL  , 1, "0000000000000000"}, //ciSD0 Entry number
        {"cISD cISD1 Entry   ", SectionTOC[cISD].Offset+0x20             , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "00000060"}, //
        {"cISD cISD1 Length  ", SectionTOC[cISD].Offset+0x24             , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "00000200"}, //
        {"cISD cISD1 NB      ", SectionTOC[cISD].Offset+0x28             , 0x08, TYPE_HEX  +DISPLAY_FAIL  , 1, "0000000000000001"}, //
        {"cISD cISD2 Entry   ", SectionTOC[cISD].Offset+0x30             , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "00000260"}, //
        {"cISD cISD2 Length  ", SectionTOC[cISD].Offset+0x34             , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "00000010"}, //
        {"cISD cISD2 NB      ", SectionTOC[cISD].Offset+0x38             , 0x08, TYPE_HEX  +DISPLAY_FAIL  , 1, "0000000000000002"}, //
        {"PS3 MAC Address    ", SectionTOC[cISD].Offset+0x40             , 0x06, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"cISD1 Magic Number ", SectionTOC[cISD].Offset+0x60             , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "7F49444C"},
        {"cISD1 Unknown      ", SectionTOC[cISD].Offset+0x64             , 0x02, TYPE_HEX  +DISPLAY_FAIL  , 1, "0002"},
        {"cISD1 Start Offset ", SectionTOC[cISD].Offset+0x66             , 0x02, TYPE_HEX  +DISPLAY_FAIL  , 1, "0060"},
        {"cISD1 Unknown      ", SectionTOC[cISD].Offset+0x68             , 0x02, TYPE_HEX  +DISPLAY_FAIL  , 1, "0100"},
        {"cISD1 0001/0002 ?  ", SectionTOC[cISD].Offset+0x6A             , 0x02, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"cISD1 -        CID ", SectionTOC[cISD].Offset+0x6C             , 0x04, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"cISD1 -       eCID ", SectionTOC[cISD].Offset+0x70             , 0x20, TYPE_ASCII+DISPLAY_ALWAYS, 0, NULL},
        {"cISD1 -   board_id ", SectionTOC[cISD].Offset+0x90             , 0x08, TYPE_ASCII+DISPLAY_ALWAYS, 0, NULL},
        {"cISD1 -   kiban_id ", SectionTOC[cISD].Offset+0x98             , 0x0C, TYPE_ASCII+DISPLAY_ALWAYS, 0, NULL},
        {"cISD1 -0x3F0A4 Data", SectionTOC[cISD].Offset+0xA4             , 0x06, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"cISD1 -0x3F0B0 Data", SectionTOC[cISD].Offset+0xB0             , 0x08, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"cISD1 - ckp_mgt_id ", SectionTOC[cISD].Offset+0xB8             , 0x08, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"cISD2 - wlan_data1 ", SectionTOC[cISD].Offset+0x0260           , 0x08, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"cISD2 - wlan_data2 ", SectionTOC[cISD].Offset+0x0268           , 0x08, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"cvtrm - pck/puk    ", SectionTOC[cvtrm].Offset+0x1D748         , 0x14, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"CELL_EXTNOR_AREA 01", SectionTOC[CELL_EXTNOR_AREA].Offset+0x10 , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "00000001"},
        {"Offset for SHA1SUM?", SectionTOC[CELL_EXTNOR_AREA].Offset+0x20 , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "00000200"},
        {"CELL_EXTNOR_AREA 44", SectionTOC[CELL_EXTNOR_AREA].Offset+0x24 , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "00000044"},
        {"CELL_EXTNOR_AREA 00", SectionTOC[CELL_EXTNOR_AREA].Offset+0x28 , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "00000000"},
        {"HDD SHA1 SUM       ", SectionTOC[CELL_EXTNOR_AREA].Offset+0x2C , 0x14, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"HDD information ?  ", SectionTOC[CELL_EXTNOR_AREA].Offset+0x200, 0x04, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"HDD information    ", SectionTOC[CELL_EXTNOR_AREA].Offset+0x204, 0x1C, TYPE_ASCII+DISPLAY_ALWAYS, 0, NULL},
        {"PS3 Serial Number  ", SectionTOC[CELL_EXTNOR_AREA].Offset+0x230, 0x10, TYPE_ASCII+DISPLAY_ALWAYS, 0, NULL},
        // http://www.ps3devwiki.com/wiki/Talk:Flash:asecure_loader
        {"Bootldr revision   ", SectionTOC[bootldr].Offset+0x04          , 0x0C, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"Bootldr binary size", SectionTOC[bootldr].Offset+0x10          , 0x04, TYPE_HEX  +DISPLAY_ALWAYS, 1, bootldrSize},
        {"Bootldr pcn        ", SectionTOC[bootldr].Offset+0x14          , 0x0C, TYPE_HEX  +DISPLAY_ALWAYS, 1, pcn},
        {"cvtrm SCEI magicnbr", SectionTOC[cvtrm].Offset                 , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "53434549"},
        {"cvtrm hdr          ", SectionTOC[cvtrm].Offset+0x004004        , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "5654524D"},
        {"cvtrm hdr bis      ", SectionTOC[cvtrm].Offset+0x024004        , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "5654524D"},
        {NULL, 0, 0, 0, 0, NULL} // 78
    };

    printf ("******************************\n");
    printf ("*      Per Console Data      *\n");
    printf ("******************************\n");

    while (SectionPerConsole[Cursor].name!=NULL)
    {
        Status |= ReadSection(SectionPerConsole[Cursor].name
                              , FileToRead
                              , SectionPerConsole[Cursor].Offset
                              , SectionPerConsole[Cursor].Size
                              , SectionPerConsole[Cursor].DisplayType
                              , SectionPerConsole[Cursor].Check
                              , SectionPerConsole[Cursor].Pattern);
        SizedCheck += SectionPerConsole[Cursor].Size;
        Cursor++;

    }

    GetSection(FileToRead, SectionTOC[asecure_loader].Offset+0x40, 0x04, TYPE_HEX, Buffer);
    Status |= ReadSection("metldr hdr",FileToRead, SectionTOC[asecure_loader].Offset+0x50, 0x04, TYPE_HEX+DISPLAY_FAIL, 1, Buffer);

    GetSection(FileToRead, SectionTOC[bootldr].Offset, 0x04, TYPE_HEX, Buffer);
    Status |= ReadSection("Bootldr hdr",FileToRead, SectionTOC[bootldr].Offset+0x10, 0x04, TYPE_HEX+DISPLAY_FAIL, 1, Buffer);

    GetSection(FileToRead, SectionTOC[eEID].Offset+0x77, 0x01, TYPE_HEX, IDPSTargetID);
    GetSection(FileToRead, SectionTOC[asecure_loader].Offset+0x1E, 0x02, TYPE_HEX, metldrOffset0);
    GetSection(FileToRead, SectionTOC[asecure_loader].Offset+0x42, 0x02, TYPE_HEX, metldrOffset1);
    GetSection(FileToRead, SectionTOC[bootldr].Offset+0x02, 0x02, TYPE_HEX, bootldrOffset0);
    GetSection(FileToRead, SectionTOC[bootldr].Offset+0x12, 0x02, TYPE_HEX, bootldrOffset1);
    //SizedCheck += 1; // 1 byte in size added for the IDPSTargetID checking

    printf ("\nData found in NOR to identify the SKU are:\n");
    //       0         1         2         3         4         5         6         7
    //       01234567890123456789012345678901234567890123456789012345678901234567890123456789
    printf ("TargetID | metldr\t     | bootldr \n");
    printf ("TargetID | Offset0 | Offset1 | Offset0 | Offset1\n");
    SetTextYELLOW();
    printf (" %7s   %7s   %7s   %7s   %7s\n\n", IDPSTargetID, metldrOffset0, metldrOffset1, bootldrOffset0, bootldrOffset1);
    SetTextNONE();

    Cursor=0;
    while (CheckPerSKU[Cursor].IDPSTargetID!=NULL)
    {
        if ((strcmp(CheckPerSKU[Cursor].IDPSTargetID,IDPSTargetID)==0)
                &&(strcmp(CheckPerSKU[Cursor].metldrOffset0,metldrOffset0)==0)
                &&(strcmp(CheckPerSKU[Cursor].metldrOffset1,metldrOffset1)==0)
                &&(strcmp(CheckPerSKU[Cursor].bootldrOffset0,bootldrOffset0)==0)
                &&(strcmp(CheckPerSKU[Cursor].bootldrOffset1,bootldrOffset1)==0))
        {
            printf ("PS3 SKU : %s minimum FW : %s (item %d in list)\n", CheckPerSKU[Cursor].SKU, CheckPerSKU[Cursor].MinFW, Cursor);
            SKUFound = 1;
        }
        Cursor++;
    }

    // if (!SKUFound){
    // printf ("Data found in NOR to identify the SKU are:\n- TargetID:'%s'\n", IDPSTargetID);
    // printf ("- metldr Offset 0:'%s'\n", metldrOffset0);
    // printf ("- metldr Offset 1:'%s'\n", metldrOffset1);
    // printf ("- bootldr Offset 0:'%s'\n", bootldrOffset0);
    // printf ("- bootldr Offset 1:'%s'\n", bootldrOffset1);
    // }

exit:

    free (Buffer);
    free (IDPSTargetID);
    free (metldrOffset0);
    free (metldrOffset1);
    free (metldrSize);
    free (bootldrOffset0);
    free (bootldrOffset1);
    free (bootldrSize);
    free (pcn);

    return Status;
}

uint8_t CheckFilledData (FILE *FileToRead, uint32_t *PercentCheck)
{
    int Cursor=0;
    int Cursor2=0;
    uint32_t SizedCheck=0;
    uint8_t Status =EXIT_SUCCESS;
    uint8_t Status2=EXIT_SUCCESS;
    uint8_t Status3=EXIT_SUCCESS;
    uint32_t bootldrSize;
    uint32_t bootldrFilledSize;
    uint32_t metldrSize;
    uint32_t metldrFilledSize;
    uint32_t trvk_prg0Size;
    uint32_t trvk_prg0FilledSize;
    uint32_t trvk_prg1Size;
    uint32_t trvk_prg1FilledSize;
    uint32_t trvk_pkg0Size;
    uint32_t trvk_pkg0FilledSize;
    uint32_t trvk_pkg1Size;
    uint32_t trvk_pkg1FilledSize;
    uint32_t ros0Size;
    uint32_t ros0FilledSize;
    uint32_t ros1Size;
    uint32_t ros1FilledSize;

    uint32_t LastFileTOC;
    uint32_t LastFileOffset;
    uint32_t LastFileSize;

    char *Buffer = malloc(DATA_BUFFER_SIZE+1);

    char *metldrOffset0    = malloc(5);
    char *bootldrOffset0   = malloc(5);
    char *trvk_prg0Offset0 = malloc(5);
    char *trvk_prg1Offset0 = malloc(5);
    char *trvk_pkg0Offset0 = malloc(5);
    char *trvk_pkg1Offset0 = malloc(5);
    //    char *ros0Offset0= malloc(5);
    //    char *ros1Offset0= malloc(5);

    printf ("******************************\n");
    printf ("* Area filled with 00 or FF  *\n");
    printf ("******************************\n");

    GetSection(FileToRead, SectionTOC[asecure_loader].Offset+0x42, 0x02, TYPE_HEX, metldrOffset0);
    metldrSize = (strtol(metldrOffset0,NULL,16))*0x10+0x40;
    metldrFilledSize = SectionTOC[eEID].Offset - metldrSize - SectionTOC[asecure_loader].Offset - 0x40;

    GetSection(FileToRead, SectionTOC[bootldr].Offset+0x02, 0x02, TYPE_HEX, bootldrOffset0);
    bootldrSize = (strtol(bootldrOffset0,NULL,16))*0x10+0x40;
    bootldrFilledSize = 0x1000000 - bootldrSize - SectionTOC[bootldr].Offset;

    GetSection(FileToRead, SectionTOC[trvk_prg0].Offset+0x0E, 0x02, TYPE_HEX, trvk_prg0Offset0);
    trvk_prg0Size = strtol(trvk_prg0Offset0,NULL,16);
    trvk_prg0FilledSize = 0x040FF0 - trvk_prg0Size - SectionTOC[trvk_prg0].Offset - 0x10;

    GetSection(FileToRead, SectionTOC[trvk_prg1].Offset+0x0E, 0x02, TYPE_HEX, trvk_prg1Offset0);
    trvk_prg1Size = strtol(trvk_prg1Offset0,NULL,16);
    trvk_prg1FilledSize = 0x060FF0 - trvk_prg1Size - SectionTOC[trvk_prg1].Offset - 0x10;

    GetSection(FileToRead, SectionTOC[trvk_pkg0].Offset+0x0E, 0x02, TYPE_HEX, trvk_pkg0Offset0);
    trvk_pkg0Size = strtol(trvk_pkg0Offset0,NULL,16);
    trvk_pkg0FilledSize = 0x080FF0 - trvk_pkg0Size - SectionTOC[trvk_pkg0].Offset - 0x10;

    GetSection(FileToRead, SectionTOC[trvk_pkg1].Offset+0x0E, 0x02, TYPE_HEX, trvk_pkg1Offset0);
    trvk_pkg1Size = strtol(trvk_pkg1Offset0,NULL,16);
    trvk_pkg1FilledSize = 0x0A0FF0 - trvk_pkg1Size - SectionTOC[trvk_pkg1].Offset - 0x10;

    //at ros0 offset + 0x14: nb of files, (nb of files) * 0x30 = size of TOC
    GetSection(FileToRead, SectionTOC[ros0].Offset+0x14, 0x04, TYPE_HEX, Buffer);
    LastFileTOC = (strtol(Buffer,NULL,16))*0x30-0x10;

    //last file position found at (ros0 offset) + (size of TOC) - 0x10
    GetSection(FileToRead, SectionTOC[ros0].Offset+LastFileTOC, 0x08, TYPE_HEX, Buffer);
    LastFileOffset = strtol(Buffer,NULL,16);

    //+ 0x8 for its size.
    GetSection(FileToRead, SectionTOC[ros0].Offset+LastFileTOC+0x08, 0x08, TYPE_HEX, Buffer);
    LastFileSize = strtol(Buffer,NULL,16);

    ros0Size = 0x10 + LastFileOffset + LastFileSize;
    //From end of last file pos + size to next section - 0x10 : full of 00
    //last 0x10 bytes are full of FF !!??

    ros0FilledSize = SectionTOC[ros1].Offset - SectionTOC[ros0].Offset - ros0Size;

    //at ros1 offset + 0x14: nb of files, (nb of files) * 0x30 = size of TOC
    GetSection(FileToRead, SectionTOC[ros1].Offset+0x14, 0x04, TYPE_HEX, Buffer);
    LastFileTOC = (strtol(Buffer,NULL,16))*0x30-0x10;
    //last file position found at (ros1 offset) + (size of TOC) - 0x10

    GetSection(FileToRead, SectionTOC[ros1].Offset+LastFileTOC, 0x08, TYPE_HEX, Buffer);
    LastFileOffset = strtol(Buffer,NULL,16);

    //+ 0x8 for its size.
    GetSection(FileToRead, SectionTOC[ros1].Offset+LastFileTOC+0x08, 0x08, TYPE_HEX, Buffer);
    LastFileSize = strtol(Buffer,NULL,16);

    ros1Size = 0x10 + LastFileOffset + LastFileSize;
    //From end of last file pos + size to next section - 0x10 : full of 00
    //last 0x10 bytes are full of FF !!??

    ros1FilledSize = SectionTOC[cvtrm].Offset - SectionTOC[ros1].Offset - ros1Size;

    struct Sections SectionFilled[] =
    {
        {"FlashHeader"     , SectionTOC[FlashStart].Offset                    , 0x10               , TYPE_HEX, 1, "00"},
        {"FlashHeader"     , SectionTOC[FlashStart].Offset+0x30               , 0x01D0             , TYPE_HEX, 1, "00"},
        {"FlashFormat"     , SectionTOC[FlashFormat].Offset+0x10              , 0x01F0             , TYPE_HEX, 1, "FF"},
        {"FlashRegion over", SectionTOC[FlashRegion].Offset+0x0220            , 0x01E0             , TYPE_HEX, 1, "00"},
        {"asecure_loader"  , SectionTOC[asecure_loader].Offset+0x40+metldrSize, metldrFilledSize   , TYPE_HEX, 1, "00"},
        {"eEID"            , SectionTOC[eEID].Offset+0x1DD0                   , 0xE230             , TYPE_HEX, 1, "FF"},
        {"cISD"            , SectionTOC[cISD].Offset+0x46                     , 0x1A               , TYPE_HEX, 1, "FF"},
        {"cISD"            , SectionTOC[cISD].Offset+0x0270                   , 0x0590             , TYPE_HEX, 1, "FF"},
        {"cCSD"            , SectionTOC[cCSD].Offset+0x20                     , 0x30               , TYPE_HEX, 1, "FF"},
        {"cCSD"            , SectionTOC[cCSD].Offset+0x50                     , 0x07B0             , TYPE_HEX, 1, "FF"},
        {"cCSD"            , SectionTOC[cCSD].Offset+0xAC                     , 0x04               , TYPE_HEX, 1, "FF"},
        {"trvk_prg0"       , SectionTOC[trvk_prg0].Offset+0x10+trvk_prg0Size  , trvk_prg0FilledSize, TYPE_HEX, 1, "xx"}, // 00
        {"trvk_prg0"       , SectionTOC[trvk_prg0].Offset+0x0FF0              , 0x01F010           , TYPE_HEX, 1, "xx"}, // FF
        {"trvk_prg1"       , SectionTOC[trvk_prg1].Offset+0x10+trvk_prg1Size  , trvk_prg1FilledSize, TYPE_HEX, 1, "xx"}, // 00
        {"trvk_prg1"       , SectionTOC[trvk_prg1].Offset+0x0FF0              , 0x01F010           , TYPE_HEX, 1, "xx"}, // FF
        {"trvk_pkg0"       , SectionTOC[trvk_pkg0].Offset+0x10+trvk_pkg0Size  , trvk_pkg0FilledSize, TYPE_HEX, 1, "xx"}, // 00
        {"trvk_pkg0"       , SectionTOC[trvk_pkg0].Offset+0x0FF0              , 0x01F010           , TYPE_HEX, 1, "xx"}, // FF
        {"trvk_pkg1"       , SectionTOC[trvk_pkg1].Offset+0x10+trvk_pkg1Size  , trvk_pkg1FilledSize, TYPE_HEX, 1, "xx"}, // 00
        {"trvk_pkg1"       , SectionTOC[trvk_pkg1].Offset+0x0FF0              , 0x01F010           , TYPE_HEX, 1, "xx"}, // FF
        {"ros0"            , SectionTOC[ros0].Offset+ ros0Size                , ros0FilledSize     , TYPE_HEX, 1, "xx"}, // 00 need to investigate
        //{"ros0"            , SectionTOC[ros0].Offset+ ros0Size+ ros0FilledSize, 0x10               , TYPE_HEX, 1, "xx"}, // FF need to investigate
        {"ros1"            , SectionTOC[ros1].Offset+ ros1Size                , ros1FilledSize     , TYPE_HEX, 1, "xx"}, // 00 need to investigate
        //{"ros1"            , SectionTOC[ros1].Offset+ ros1Size+ ros1FilledSize, 0x10               , TYPE_HEX, 1, "xx"}, // FF need to investigate
        //{"cvtrm"           , 0xECxxxx                                         , 0x0xxxxx           , TYPE_HEX, 1, "00"}, // need to investigate
        {"CELL_EXTNOR_AREA", SectionTOC[CELL_EXTNOR_AREA].Offset+0x40         , 0x01C0             , TYPE_HEX, 1, "00"},
        {"CELL_EXTNOR_AREA", SectionTOC[CELL_EXTNOR_AREA].Offset+0x0240       , 0x01FDC0           , TYPE_HEX, 1, "00"},
        {"CELL_EXTNOR_AREA", SectionTOC[CRL1].Offset+0x30                     , 0x01FFD0           , TYPE_HEX, 1, "00"},
        {"CELL_EXTNOR_AREA", SectionTOC[DRL1].Offset+0x60                     , 0x93A0             , TYPE_HEX, 1, "00"}, // need to calculate the correct start, size seems to be found at 0xF60000E on 2 bytes ?
        {"CELL_EXTNOR_AREA", SectionTOC[DRL1].Offset+0x9408                   , 0x28               , TYPE_HEX, 1, "00"},
        {"CELL_EXTNOR_AREA", SectionTOC[DRL1].Offset+0x9530                   , 0x06D0             , TYPE_HEX, 1, "00"},
        {"CELL_EXTNOR_AREA", SectionTOC[DRL1].Offset+0x9C00                   , 0x015400           , TYPE_HEX, 1, "FF"},
        {"CELL_EXTNOR_AREA", SectionTOC[CRL2].Offset+0x30                     , 0x01FFD0           , TYPE_HEX, 1, "00"},
        {"CELL_EXTNOR_AREA", SectionTOC[DRL2].Offset+0x60                     , 0x93A0             , TYPE_HEX, 1, "00"}, // need to calculate the correct start, size seems to be found at 0xFA0000E on 2 bytes ?
        {"CELL_EXTNOR_AREA", SectionTOC[DRL2].Offset+0x9408                   , 0x28               , TYPE_HEX, 1, "00"},
        {"CELL_EXTNOR_AREA", SectionTOC[DRL2].Offset+0x9530                   , 0x06D0             , TYPE_HEX, 1, "00"},
        {"CELL_EXTNOR_AREA", SectionTOC[DRL2].Offset+0x9C00                   , 0x015400           , TYPE_HEX, 1, "FF"},
        {"CELL_EXTNOR_AREA", SectionTOC[CELL_EXTNOR_AREA].Offset+0x09F000     , 0x1000             , TYPE_HEX, 1, "FF"},
        {"bootldr"         , SectionTOC[bootldr].Offset+bootldrSize           , bootldrFilledSize  , TYPE_HEX, 1, "FF"},
        {NULL, 0, 0, 0, 0, NULL}
    };

    while (SectionFilled[Cursor].name!=NULL)
    {
        Status3 = EXIT_SUCCESS;
        if (strcmp(SectionFilled[Cursor].Pattern,"xx")==0)
        {
            for (Cursor2=0; Cursor2<SectionFilled[Cursor].Size; Cursor2++)
            {
                Status2 = !((ReadSection(SectionFilled[Cursor].name
                                         , FileToRead
                                         , SectionFilled[Cursor].Offset+Cursor2
                                         , 0x01
                                         , SectionFilled[Cursor].DisplayType
                                         , SectionFilled[Cursor].Check
                                         , "00"))
                            ^ (ReadSection(SectionFilled[Cursor].name
                                           , FileToRead
                                           , SectionFilled[Cursor].Offset+Cursor2
                                           , 0x01
                                           , SectionFilled[Cursor].DisplayType
                                           , SectionFilled[Cursor].Check
                                           , "FF")));
                if ((Status2)&&(!Verbose))
                {
                    GetSection (FileToRead
                                , SectionFilled[Cursor].Offset+Cursor2
                                , 0x01
                                , SectionFilled[Cursor].DisplayType
                                , Buffer);
                    printf ("Error at '0x%08X' found :'0x%02X'\n", SectionFilled[Cursor].Offset+Cursor2, *Buffer);
                }
                Status3 |= Status2;
            }
            if (!Status3)
            {
                printf ("'%16s' from '0x%08X' to '0x%08X' is empty (00 / FF) ! "
                        , SectionFilled[Cursor].name
                        , SectionFilled[Cursor].Offset
                        , SectionFilled[Cursor].Offset+SectionFilled[Cursor].Size);
                printStatus ("GOOD", GOOD);
                printf ("\n");
            }
            else
            {
                printf ("'%16s' from '0x%08X' to '0x%08X' ! "
                        , SectionFilled[Cursor].name
                        , SectionFilled[Cursor].Offset
                        , SectionFilled[Cursor].Offset+SectionFilled[Cursor].Size);
                printStatus ("FAIL", FAILURE);
                printf ("\n");
            }

        }
        else
        {
            for (Cursor2=0; Cursor2<SectionFilled[Cursor].Size; Cursor2++)
            {
                Status2 = ReadSection(SectionFilled[Cursor].name
                                      , FileToRead
                                      , SectionFilled[Cursor].Offset+Cursor2
                                      , 0x01
                                      , SectionFilled[Cursor].DisplayType
                                      , SectionFilled[Cursor].Check
                                      , SectionFilled[Cursor].Pattern);
                if (Status2)
                {
                    GetSection (FileToRead
                                , SectionFilled[Cursor].Offset+Cursor2
                                , 0x01
                                , SectionFilled[Cursor].DisplayType
                                , Buffer);
                    printf ("Error at '0x%08X' found :'0x%02X'\n", SectionFilled[Cursor].Offset+Cursor2, *Buffer);
                }
                Status3 |= Status2;
            }
            if (!Status3)
            {
                printf ("'%16s' from '0x%08X' to '0x%08X' is full of '0x%s' ! "
                        , SectionFilled[Cursor].name
                        , SectionFilled[Cursor].Offset
                        , SectionFilled[Cursor].Offset+SectionFilled[Cursor].Size
                        , SectionFilled[Cursor].Pattern);
                printStatus ("GOOD", GOOD);
                printf ("\n");
            }
            else
            {
                printf ("'%16s' from '0x%08X' to '0x%08X' ! "
                        , SectionFilled[Cursor].name
                        , SectionFilled[Cursor].Offset
                        , SectionFilled[Cursor].Offset+SectionFilled[Cursor].Size);
                printStatus ("FAIL", FAILURE);
                printf ("\n");
            }
        }

        Cursor++;
        Status |= Status3;
        SizedCheck += SectionFilled[Cursor].Size;
    }

exit:
    free (Buffer);
    free (metldrOffset0);
    free (bootldrOffset0);
    free (trvk_prg0Offset0);
    free (trvk_prg1Offset0);
    free (trvk_pkg0Offset0);
    free (trvk_pkg1Offset0);
    //free (ros0Offset0);
    //free (ros1Offset0);

    return Status;
}

uint8_t CheckPerFW (FILE *FileToRead, uint32_t *PercentCheck)
{
    uint16_t Cursor=0;
    uint32_t SizedCheck=0;

    uint8_t Status = EXIT_SUCCESS;
    int8_t MD5Found = NOT_FOUND;

    uint8_t MD5result[MD5_DIGEST_LENGTH];

    uint8_t NbFileTOCros0;
    uint8_t NbFileTOCros1;

    uint32_t trvk_prg0Size;
    uint32_t trvk_prg1Size;
    uint32_t trvk_pkg0Size;
    uint32_t trvk_pkg1Size;

    char FileNameToExtract[0x40]= {0};

    //char  ROS0SDKVersion[]="3.55";
    //char  ROS1SDKVersion[]="3.41";

    char *Buffer;
    Buffer = malloc(DATA_BUFFER_SIZE+1);

    struct Sections SectionRos0[NB_MAX_FILE_ROS+1] =
    {
        {NULL, 0, 0, 0, 0, NULL}
    };

    struct Sections SectionRos1[NB_MAX_FILE_ROS+1] =
    {
        {NULL, 0, 0, 0, 0, NULL}
    };

    printf ("******************************\n");
    printf ("*     Per Firmware Data      *\n");
    printf ("******************************\n");
    /////////////////////////////////////////////////////////////////////////
    //  only for NAND -> http://www.ps3devwiki.com/wiki/Flash:ROS#Header   //
    /////////////////////////////////////////////////////////////////////////

    //http://www.ps3devwiki.com/wiki/Flash:ROS#ros_Entries
    //at ros0 offset + 0x14: nb of files, (nb of files) * 0x30 = size of TOC
    GetSection(FileToRead, SectionTOC[ros0].Offset+0x14, 0x04, TYPE_HEX, Buffer);
    NbFileTOCros0 = strtol(Buffer,NULL,16);

    SizedCheck += 0x04;

    if (NbFileTOCros0<NB_MAX_FILE_ROS)
    {
        for (Cursor=0; Cursor<NbFileTOCros0; Cursor++)
        {
            //www.ps3devwiki.com/wiki/Flash:ROS#Entry_Table

            GetSection(FileToRead, SectionTOC[ros0].Offset+0x20+Cursor*0x30, 0x08, TYPE_HEX, Buffer);
            SectionRos0[Cursor].Offset = strtol(Buffer,NULL,16) + SectionTOC[ros0].Offset + 0x10;

            GetSection(FileToRead, SectionTOC[ros0].Offset+0x28+Cursor*0x30, 0x08, TYPE_HEX, Buffer);
            SectionRos0[Cursor].Size = strtol(Buffer,NULL,16);

            GetSection(FileToRead, SectionTOC[ros0].Offset+0x30+Cursor*0x30, 0x20, TYPE_ASCII, Buffer);
            SectionRos0[Cursor].name = strdup(Buffer);

            SizedCheck += SectionRos0[Cursor].Size;
        }
    }
    else
    {
        printf ("Found %d files in the TOC of ros0, max is %d ! " , NbFileTOCros0 , NB_MAX_FILE_ROS);
        printStatus ("FAIL", FAILURE);
        printf ("\n");
        goto exit;
    }

    GetSection(FileToRead, SectionTOC[ros1].Offset+0x14, 0x04, TYPE_HEX, Buffer);
    NbFileTOCros1 = strtol(Buffer,NULL,16);

    SizedCheck += 0x04;

    if (NbFileTOCros1<NB_MAX_FILE_ROS)
    {
        for (Cursor=0; Cursor<NbFileTOCros1; Cursor++)
        {
            //http://www.ps3devwiki.com/wiki/Flash:ROS#Entry_Table

            GetSection(FileToRead, SectionTOC[ros1].Offset+0x20+Cursor*0x30, 0x08, TYPE_HEX, Buffer);
            SectionRos1[Cursor].Offset = strtol(Buffer,NULL,16) + SectionTOC[ros1].Offset + 0x10;

            GetSection(FileToRead, SectionTOC[ros1].Offset+0x28+Cursor*0x30, 0x08, TYPE_HEX, Buffer);
            SectionRos1[Cursor].Size = strtol(Buffer,NULL,16);

            GetSection(FileToRead, SectionTOC[ros1].Offset+0x30+Cursor*0x30, 0x20, TYPE_ASCII, Buffer);
            SectionRos1[Cursor].name=strdup(Buffer);

            SizedCheck += SectionRos1[Cursor].Size;
        }
    }
    else
    {
        printf ("Found %d files in the TOC of ros1, max is %d ! " , NbFileTOCros1 , NB_MAX_FILE_ROS);
        printStatus ("FAIL", FAILURE);
        printf ("\n");
        goto exit;
    }
    GetSection(FileToRead, SectionTOC[trvk_prg0].Offset+0x0E, 0x02, TYPE_HEX, Buffer);
    trvk_prg0Size = strtol(Buffer,NULL,16);

    GetSection(FileToRead, SectionTOC[trvk_prg1].Offset+0x0E, 0x02, TYPE_HEX, Buffer);
    trvk_prg1Size = strtol(Buffer,NULL,16);

    GetSection(FileToRead, SectionTOC[trvk_pkg0].Offset+0x0E, 0x02, TYPE_HEX, Buffer);
    trvk_pkg0Size = strtol(Buffer,NULL,16);

    GetSection(FileToRead, SectionTOC[trvk_pkg1].Offset+0x0E, 0x02, TYPE_HEX, Buffer);
    trvk_pkg1Size = strtol(Buffer,NULL,16);

    printf ("Short MD5 checking for revokation\n");
    //http://www.ps3devwiki.com/wiki/Flash:Revoke_Package#trvk_prg0
    if (!ReadSection("trvk_prg0 SCE hdr" , FileToRead , SectionTOC[trvk_prg0].Offset+0x10, 0x04 , TYPE_HEX+DISPLAY_FAIL , 1 , "53434500"))
    {
        GetSection(FileToRead, SectionTOC[trvk_prg0].Offset+0x0E, 0x02, TYPE_HEX, Buffer);
        trvk_prg0Size = strtol(Buffer,NULL,16);
        MD5Found = NOT_BROKEN;

        MD5SumFileSection (FileToRead, SectionTOC[trvk_prg0].Offset+0x10, 0x0FE0, MD5result);
        SetTextYELLOW ();
        printMD5(MD5result);
        SetTextNONE ();

        Cursor = 0;
        while ( (trvk_prg_MD5[Cursor].MD5!=NULL) && (MD5Found==NOT_BROKEN) )
        {
            if (CompareMD5(MD5result, trvk_prg_MD5[Cursor].MD5)==0)
            {
                MD5Found = Cursor;
            }
            //else{
            // do something useful...
            // NORFileName+trvk_prg0
            //sprintf (FileNameToExtract,"%s_trvk_prg0.bin",NORFileName);
            //else ( it's not good do something even smarter like
            //      ExtractSection(FileNameToExtract, FileToRead, SectionTOC[trvk_prg0].Offset+0x10, trvk_prg0Size);
            //  printf ("you can find the suspect file here:'%s', use any tools like scetool to checkit in detail", file+path);
            //}
            Cursor++;
        }
    }
    else
    {
        MD5Found = IS_BROKEN;
    }

    if (MD5Found == IS_BROKEN)
    {
        printf (" trvk_prg0's header is broken ! ");
        printStatus ("FAIL", FAILURE);
        printf ("\n");
        Status = EXIT_FAILURE;
        MD5Found = NOT_FOUND;
    }
    else if (MD5Found == NOT_BROKEN)
    {
        printf (" trvk_prg0 unknown but good header ! ");
        printStatus ("WARNING", WARNING);
        printf ("\n");
        Status = EXIT_FAILURE;
        MD5Found = NOT_FOUND;
    }
    else if (MD5Found == NOT_FOUND)
    {
        printf (" trvk_prg0 unknown ! ");
        printStatus ("FAIL", FAILURE);
        printf ("\n");
        Status = EXIT_FAILURE;
    }
    else
    {
        printf (" trvk_prg0 for FW :'%s' ! ",trvk_prg_MD5[MD5Found].Version);
        printStatus ("GOOD", GOOD);
        printf ("\n");
        MD5Found = NOT_FOUND;
    }

    //http://www.ps3devwiki.com/wiki/Flash:Revoke_Package#trvk_prg1
    // No need to check the section if its header is broken
    if (!ReadSection("trvk_prg1 SCE hdr" , FileToRead , SectionTOC[trvk_prg1].Offset+0x10, 0x04 , TYPE_HEX+DISPLAY_FAIL , 1 , "53434500"))
    {
        GetSection(FileToRead, SectionTOC[trvk_prg1].Offset+0x0E, 0x02, TYPE_HEX, Buffer);
        trvk_prg1Size = strtol(Buffer,NULL,16);
        MD5Found = NOT_BROKEN;

        MD5SumFileSection (FileToRead, SectionTOC[trvk_prg1].Offset+0x10, 0x0FE0, MD5result);
        SetTextYELLOW ();
        printMD5(MD5result);
        SetTextNONE ();
        Cursor = 0;
        while ( (trvk_prg_MD5[Cursor].MD5!=NULL) && (MD5Found==NOT_BROKEN) )
        {
            if (CompareMD5(MD5result, trvk_prg_MD5[Cursor].MD5)==0)
            {
                MD5Found = Cursor;
            }
            //else ( it's not good do something even smarter like
            //      ExtractSection(SectionRos[Cursor].name, FileToRead, SectionTOC[trvk_prg1].Offset+0x10, trvk_prg1Size);
            //  printf ("you can find the suspect file here:'%s', use any tools like scetool to checkit in detail", file+path);
            //}
            Cursor++;
        }
    }
    else
    {
        MD5Found = IS_BROKEN;
    }

    if (MD5Found == IS_BROKEN)
    {
        printf (" trvk_prg1's header is broken ! ");
        printStatus ("FAIL", FAILURE);
        printf ("\n");
        Status = EXIT_FAILURE;
        MD5Found = NOT_FOUND;
    }
    else if (MD5Found == NOT_BROKEN)
    {
        printf (" trvk_prg1 unknown but good header ! ");
        printStatus ("WARNING", WARNING);
        printf ("\n");
        Status = EXIT_FAILURE;
        MD5Found = NOT_FOUND;
    }
    else if (MD5Found == NOT_FOUND)
    {
        printf (" trvk_prg1 unknown ! ");
        printStatus ("FAIL", FAILURE);
        printf ("\n");
        Status = EXIT_FAILURE;
    }
    else
    {
        printf (" trvk_prg1 for FW :'%s' ! ",trvk_prg_MD5[MD5Found].Version);
        printStatus ("GOOD", GOOD);
        printf ("\n");
        MD5Found = NOT_FOUND;
    }

    //http://www.ps3devwiki.com/wiki/Flash:Revoke_Package#trvk_pkg0
    // No need to check the section if its header is broken
    if (!ReadSection("trvk_pkg0 SCE hdr" , FileToRead , SectionTOC[trvk_pkg0].Offset+0x10, 0x04 , TYPE_HEX+DISPLAY_FAIL , 1 , "53434500"))
    {
        GetSection(FileToRead, SectionTOC[trvk_pkg0].Offset+0x0E, 0x02, TYPE_HEX, Buffer);
        trvk_pkg0Size = strtol(Buffer,NULL,16);
        MD5Found = NOT_BROKEN;

        MD5SumFileSection (FileToRead, SectionTOC[trvk_pkg0].Offset+0x10, 0x0FE0, MD5result);
        SetTextYELLOW ();
        printMD5(MD5result);
        SetTextNONE ();
        Cursor = 0;
        while ( (trvk_pkg_MD5[Cursor].MD5!=NULL) && (MD5Found==NOT_BROKEN) )
        {
            if (CompareMD5(MD5result, trvk_pkg_MD5[Cursor].MD5)==0)
            {
                MD5Found = Cursor;
            }
            //else ( it's not good do something even smarter like
            //      ExtractSection(SectionRos[Cursor].name, FileToRead, SectionTOC[trvk_pkg0].Offset+0x10, trvk_pkg0Size);
            //  printf ("you can find the suspect file here:'%s', use any tools like scetool to checkit in detail", file+path);
            //}
            Cursor++;
        }
    }
    else
    {
        MD5Found = IS_BROKEN;
    }

    if (MD5Found == IS_BROKEN)
    {
        printf (" trvk_pkg0's header is broken ! ");
        printStatus ("FAIL", FAILURE);
        printf ("\n");
        Status = EXIT_FAILURE;
        MD5Found = NOT_FOUND;
    }
    else if (MD5Found == NOT_BROKEN)
    {
        printf (" trvk_pkg0 unknown but good header ! ");
        printStatus ("WARNING", WARNING);
        printf ("\n");
        Status = EXIT_FAILURE;
        MD5Found = NOT_FOUND;
    }
    else if (MD5Found == NOT_FOUND)
    {
        printf (" trvk_pkg0 unknown ! ");
        printStatus ("FAIL", FAILURE);
        printf ("\n");
        Status = EXIT_FAILURE;
    }
    else
    {
        printf (" trvk_pkg0 for FW :'%s' ! ",trvk_pkg_MD5[MD5Found].Version);
        printStatus ("GOOD", GOOD);
        printf ("\n");
        MD5Found = NOT_FOUND;
    }

    //http://www.ps3devwiki.com/wiki/Flash:Revoke_Package#trvk_pkg1
    // No need to check the section if its header is broken
    if (!ReadSection("trvk_pkg1 SCE hdr" , FileToRead , SectionTOC[trvk_pkg1].Offset+0x10, 0x04 , TYPE_HEX+DISPLAY_FAIL , 1 , "53434500"))
    {
        GetSection(FileToRead, SectionTOC[trvk_pkg1].Offset+0x0E, 0x02, TYPE_HEX, Buffer);
        trvk_pkg1Size = strtol(Buffer,NULL,16);
        MD5Found = NOT_BROKEN;

        MD5SumFileSection (FileToRead, SectionTOC[trvk_pkg1].Offset+0x10, 0x0FE0, MD5result);
        SetTextYELLOW ();
        printMD5(MD5result);
        SetTextNONE ();
        Cursor = 0;
        while ( (trvk_pkg_MD5[Cursor].MD5!=NULL) && (MD5Found==NOT_BROKEN) )
        {
            if (CompareMD5(MD5result, trvk_pkg_MD5[Cursor].MD5)==0)
            {
                MD5Found = Cursor;
            }

            //else ( it's not good do something even smarter like
            //      ExtractSection(SectionRos[Cursor].name, FileToRead, SectionTOC[trvk_pkg1].Offset+0x10, trvk_pkg1Size);
            //  printf ("you can find the suspect file here:'%s', use any tools like scetool to checkit in detail", file+path);
            //}
            Cursor++;
        }
    }
    else
    {
        MD5Found = IS_BROKEN;
    }

    if (MD5Found == IS_BROKEN)
    {
        printf (" trvk_pkg1's header is broken ! ");
        printStatus ("FAIL", FAILURE);
        printf ("\n");
        Status = EXIT_FAILURE;
        MD5Found = NOT_FOUND;
    }
    else if (MD5Found == NOT_BROKEN)
    {
        printf (" trvk_pkg1 unknown but good header ! ");
        printStatus ("WARNING", WARNING);
        printf ("\n");
        Status = EXIT_FAILURE;
        MD5Found = NOT_FOUND;
    }
    else if (MD5Found == NOT_FOUND)
    {
        printf (" trvk_pkg1 unknown ! ");
        printStatus ("FAIL", FAILURE);
        printf ("\n");
        Status = EXIT_FAILURE;
    }
    else
    {
        printf (" trvk_pkg1 for FW :'%s' ! ",trvk_pkg_MD5[MD5Found].Version);
        printStatus ("GOOD", GOOD);
        printf ("\n");
        MD5Found = NOT_FOUND;
    }

    //Cursor = 0;
    //while (SectionRos[Cursor].name!=NULL)
    //{
//        if (strcmp(SectionRos[Cursor].name, "sdk_version")==0)
//        {
//            GetSection(FileToRead, SectionRos[Cursor].Offset, SectionRos[Cursor].Size, TYPE_ASCII, Buffer);
//            if (Cursor<=NbFileTOCros0-1)
//            {
//                ROS0SDKVersion[0]=Buffer[0];
//                ROS0SDKVersion[2]=Buffer[1];
//                ROS0SDKVersion[3]=Buffer[2];
//            }
//            else
//            {
//                ROS1SDKVersion[0]=Buffer[0];
//                ROS1SDKVersion[2]=Buffer[1];
//                ROS1SDKVersion[3]=Buffer[2];
//            }
//        }
//        Cursor++;
    //}

    printf ("Short MD5 checking for core os 0 files\n");
    Cursor = 0;
    while (SectionRos0[Cursor].name!=NULL)
    {
        MD5SumFileSection ( FileToRead, SectionRos0[Cursor].Offset, SectionRos0[Cursor].Size, MD5result);

        SetTextYELLOW ();
        printMD5(MD5result);
        SetTextNONE ();
        printf (" '%s'",SectionRos0[Cursor].name);
        if (strcmp(SectionRos0[Cursor].name, "sdk_version")==0)
        {
            GetSection(FileToRead, SectionRos0[Cursor].Offset, SectionRos0[Cursor].Size, TYPE_ASCII, Buffer);
            printf (" SDK '%c.%c%c'", Buffer[0], Buffer[1], Buffer[2]);
        }
        printf("\n");
//        if (Cursor<=NbFileTOCros0-1)
//        {
//            printf ("SDK '%c.%c%c' | MD5 '", ROS0SDKVersion[0],ROS0SDKVersion[2],ROS0SDKVersion[3]);
//        }
//        else
//        {
//            printf ("SDK '%c.%c%c' | MD5 '", ROS1SDKVersion[0],ROS1SDKVersion[2],ROS1SDKVersion[3]);
//        }
        // Compare MD5 with known ones
        //if (      ) {//   It's good, do something smart like

        //      printf ("\t! \e[32mGOOD\e[m !\n");
        //}
        //else ( it's not good do something even smarter like
        //      ExtractSection(SectionRos[Cursor].name, BinaryFile, SectionRos[Cursor].Offset, SectionRos[Cursor].Size);
        //  printf ("you can find the suspect file here:'%s', use any tools like scetool to checkit in detail", file+path);
        //}
        Cursor++;
    }

    printf ("Short MD5 checking for core os 1 files\n");
    Cursor = 0;
    while (SectionRos1[Cursor].name!=NULL)
    {
        MD5SumFileSection ( FileToRead, SectionRos1[Cursor].Offset, SectionRos1[Cursor].Size, MD5result);

        SetTextYELLOW ();
        printMD5(MD5result);
        SetTextNONE ();
        printf (" '%s'",SectionRos1[Cursor].name);
        if (strcmp(SectionRos1[Cursor].name, "sdk_version")==0)
        {
            GetSection(FileToRead, SectionRos1[Cursor].Offset, SectionRos1[Cursor].Size, TYPE_ASCII, Buffer);
            printf (" SDK '%c.%c%c'", Buffer[0], Buffer[1], Buffer[2]);
        }
        printf("\n");
        Cursor++;
    }
    // The MD5 is done on 0x0FE0, but some blanks where checked before in CheckFilledData()
    // To avoid having a false report on the size checked here we do count on the size of data only

    SizedCheck += trvk_prg0Size;
    SizedCheck += trvk_prg1Size;
    SizedCheck += trvk_pkg0Size;
    SizedCheck += trvk_pkg1Size;

exit:
    *PercentCheck = SizedCheck;

    free (Buffer);
    return Status;
}

uint8_t CheckNotZero (FILE *FileToRead, uint32_t *PercentCheck)
{
    int Cursor=0;
    int Cursor2=0;
    uint32_t SizedCheck=0;
    uint8_t Status =EXIT_SUCCESS;
    uint8_t Status2=EXIT_SUCCESS;
    uint8_t Status3=EXIT_SUCCESS;
    uint32_t bootldrSize;
    uint32_t bootldrFilledSize;
    uint32_t metldrSize;
    uint32_t metldrFilledSize;
    //uint32_t trvk_prg0Size;
    //uint32_t trvk_prg0FilledSize;
    //uint32_t trvk_prg1Size;
    //uint32_t trvk_prg1FilledSize;
    //uint32_t trvk_pkg0Size;
    //uint32_t trvk_pkg0FilledSize;
    //uint32_t trvk_pkg1Size;
    //uint32_t trvk_pkg1FilledSize;
    uint32_t ros0Size;
    uint32_t ros0FilledSize;
    uint32_t ros1Size;
    uint32_t ros1FilledSize;

    uint32_t LastFileTOC;
    uint32_t LastFileOffset;
    uint32_t LastFileSize;

    char *Buffer = malloc(DATA_BUFFER_SIZE+1);
    char pattern_zz[] = "zzzzzzzz";
    char pattern_00[] = "00000000";
    char pattern_FF[] = "FFFFFFFF";

    char *OCRL0200_Pattern1=NULL;
    char *OCRL0200_Pattern2=NULL;

    char *metldrOffset0    = malloc(5);
    char *bootldrOffset0   = malloc(5);
    //char *trvk_prg0Offset0 = malloc(5);
    //char *trvk_prg1Offset0 = malloc(5);
    //char *trvk_pkg0Offset0 = malloc(5);
    //char *trvk_pkg1Offset0 = malloc(5);

    printf ("******************************\n");
    printf ("*       Not Empty Area       *\n");
    printf ("******************************\n");

    GetSection(FileToRead, SectionTOC[asecure_loader].Offset+0x42, 0x02, TYPE_HEX, metldrOffset0);
    metldrSize = (strtol(metldrOffset0,NULL,16))*0x10+0x40;
    metldrFilledSize = SectionTOC[eEID].Offset - metldrSize - SectionTOC[asecure_loader].Offset - 0x40;

    GetSection(FileToRead, SectionTOC[bootldr].Offset+0x02, 0x02, TYPE_HEX, bootldrOffset0);
    bootldrSize = (strtol(bootldrOffset0,NULL,16))*0x10+0x40;
    bootldrFilledSize = 0x1000000 - bootldrSize - SectionTOC[bootldr].Offset;

    /////////////////////////////////////////////////////////////////////////
    //  only for NAND -> http://www.ps3devwiki.com/wiki/Flash:ROS#Header   //
    /////////////////////////////////////////////////////////////////////////

    //http://www.ps3devwiki.com/wiki/Flash:ROS#ros_Entries
    //at ros0 offset + 0x14: nb of files, (nb of files) * 0x30 = size of TOC
    GetSection(FileToRead, SectionTOC[ros0].Offset+0x14, 0x04, TYPE_HEX, Buffer);
    LastFileTOC = (strtol(Buffer,NULL,16))*0x30-0x10;

    //last file position found at (ros0 offset) + (size of TOC) - 0x10
    GetSection(FileToRead, SectionTOC[ros0].Offset+LastFileTOC, 0x08, TYPE_HEX, Buffer);
    LastFileOffset = strtol(Buffer,NULL,16);

    //+ 0x8 for its size.
    GetSection(FileToRead, SectionTOC[ros0].Offset+LastFileTOC+0x08, 0x08, TYPE_HEX, Buffer);
    LastFileSize = strtol(Buffer,NULL,16);

    ros0Size = 0x10 + LastFileOffset + LastFileSize;
    //From end of last file pos + size to next section - 0x10 : full of 00
    //last 0x10 bytes are full of FF !!??

    ros0FilledSize = SectionTOC[ros1].Offset - SectionTOC[ros0].Offset - ros0Size;

    //at ros1 offset + 0x14: nb of files, (nb of files) * 0x30 = size of TOC
    GetSection(FileToRead, SectionTOC[ros1].Offset+0x14, 0x04, TYPE_HEX, Buffer);
    LastFileTOC = (strtol(Buffer,NULL,16))*0x30-0x10;
    //last file position found at (ros1 offset) + (size of TOC) - 0x10

    GetSection(FileToRead, SectionTOC[ros1].Offset+LastFileTOC, 0x08, TYPE_HEX, Buffer);
    LastFileOffset = strtol(Buffer,NULL,16);

    //+ 0x8 for its size.
    GetSection(FileToRead, SectionTOC[ros1].Offset+LastFileTOC+0x08, 0x08, TYPE_HEX, Buffer);
    LastFileSize = strtol(Buffer,NULL,16);

    ros1Size = 0x10 + LastFileOffset + LastFileSize;
    //From end of last file pos + size to next section - 0x10 : full of 00
    //last 0x10 bytes are full of FF !!??

    ros1FilledSize = SectionTOC[cvtrm].Offset - SectionTOC[ros1].Offset - ros1Size;

    //F69400 0x08 "OCRL0200" -> F69430 0x0110 non zero: OCRL0200 data
    GetSection(FileToRead, SectionTOC[DRL1].Offset+0x9400, 0x08, TYPE_ASCII, Buffer);
    if(strcmp(Buffer,"OCRL0200")==0)
    {
        OCRL0200_Pattern1 = pattern_zz;
    }
    else
    {
        OCRL0200_Pattern1 = pattern_00;
    }

    //FA9400 0x08 "OCRL0200" -> FA9430 0x0110 non zero: OCRL0200 data

    GetSection(FileToRead, SectionTOC[DRL2].Offset+0x9400, 0x08, TYPE_ASCII, Buffer);

    if(strcmp(Buffer,"OCRL0200")==0)
    {
        OCRL0200_Pattern2 = pattern_zz;

    }
    else
    {
        OCRL0200_Pattern2 = pattern_00;
    }

    struct Sections SectionFilled[] =
    {
        {"asecure_loader"  , SectionTOC[asecure_loader].Offset+0x40            , metldrSize         , TYPE_HEX, 1, pattern_zz},
        {"eEID"            , SectionTOC[eEID].Offset+0x90                      , 0x0AE0             , TYPE_HEX, 1, pattern_zz},
        {"eEID"            , SectionTOC[eEID].Offset+0x0B90                    , 0x0710             , TYPE_HEX, 1, pattern_zz},
        {"eEID"            , SectionTOC[eEID].Offset+0x12C0                    , 0xE0               , TYPE_HEX, 1, pattern_zz},
        {"eEID"            , SectionTOC[eEID].Offset+0x13A0                    , 0x30               , TYPE_HEX, 1, pattern_zz},
        {"eEID"            , SectionTOC[eEID].Offset+0x13F0                    , 0x09E0             , TYPE_HEX, 1, pattern_zz},
        //{"eEID"            , 0x02FB90                                         , 0x0710             , TYPE_HEX, 1, pattern_zz},
        //{"cISD"            , 0x03F270                                         , 0x0590             , TYPE_HEX, 1, "FF"},
        //{"cCSD"            , 0x03F850                                         , 0x07B0             , TYPE_HEX, 1, "FF"},
        //{"trvk_pkg1"       , 0x0A0FF0                                         , 0x01F010           , TYPE_HEX, 1, pattern_zz}, // FF
        //{"cvtrm"           , 0xECxxxx                                         , 0x0xxxxx           , TYPE_HEX, 1, "00"}, // need to investigate
        {"CELL_EXTNOR_AREA", SectionTOC[CELL_EXTNOR_AREA].Offset+0x0200        , 0x40               , TYPE_HEX, 1, pattern_zz},
        {"CRL1"            , SectionTOC[CRL1].Offset                           , 0x30               , TYPE_HEX, 1, pattern_zz},
        // need to calculate the correct start, size seems to be found at 0xF60000E on 2 bytes ?
        {"DRL1"            , SectionTOC[DRL1].Offset                           , 0x60               , TYPE_HEX, 1, pattern_zz},
        {"OCRL0200"        , SectionTOC[DRL1].Offset+0x9430                    , 0x0110             , TYPE_HEX, 1, OCRL0200_Pattern1},
        {"CELL_EXTNOR_AREA", SectionTOC[DRL1].Offset+0x01F000                  , 0x1000             , TYPE_HEX, 1, pattern_zz},
        {"CRL2"            , SectionTOC[CRL2].Offset                           , 0x30               , TYPE_HEX, 1, pattern_zz},
        {"DRL2"            , SectionTOC[DRL2].Offset                           , 0x60               , TYPE_HEX, 1, pattern_zz},
        // need to calculate the correct start, size seems to be found at 0xFA0000E on 2 bytes ?
        {"OCRL0200"        , SectionTOC[DRL2].Offset+0x9430                    , 0x0110             , TYPE_HEX, 1, OCRL0200_Pattern2},
        {"CELL_EXTNOR_AREA", SectionTOC[DRL2].Offset+0x01F000                  , 0x1000             , TYPE_HEX, 1, pattern_zz},
        {"bootldr"         , SectionTOC[bootldr].Offset+0x40                   , bootldrSize        , TYPE_HEX, 1, pattern_zz},

        {NULL, 0, 0, 0, 0, NULL}
    };

    while (SectionFilled[Cursor].name!=NULL)
    {
        Status3 = EXIT_SUCCESS;
        if (strcmp(SectionFilled[Cursor].Pattern,pattern_zz)==0)
        {
            for (Cursor2=0; Cursor2<SectionFilled[Cursor].Size; Cursor2+=0x4)
            {
                Status2 = !((ReadSection(SectionFilled[Cursor].name
                                         , FileToRead
                                         , SectionFilled[Cursor].Offset+Cursor2
                                         , 0x04
                                         , SectionFilled[Cursor].DisplayType
                                         , SectionFilled[Cursor].Check
                                         , pattern_00))
                            | (ReadSection(SectionFilled[Cursor].name
                                           , FileToRead
                                           , SectionFilled[Cursor].Offset+Cursor2
                                           , 0x04
                                           , SectionFilled[Cursor].DisplayType
                                           , SectionFilled[Cursor].Check
                                           , pattern_FF)));
                if (Status2)
                {
                    GetSection (FileToRead
                                , SectionFilled[Cursor].Offset+Cursor2
                                , 0x04
                                , SectionFilled[Cursor].DisplayType
                                , Buffer);
                    printf ("Error at '0x%08X' found :'0x%08X' !  ", SectionFilled[Cursor].Offset+Cursor2, *Buffer);
                    printStatus ("FAIL", FAILURE);
                    printf("\n");
                }
                Status3 |= Status2;
            }
            if (!Status3)
            {
                printf ("'%16s' from '0x%08X' to '0x%08X' is not empty ! "
                        , SectionFilled[Cursor].name
                        , SectionFilled[Cursor].Offset
                        , SectionFilled[Cursor].Offset+SectionFilled[Cursor].Size);
                printStatus ("GOOD", GOOD);
                printf("\n");
            }
            else
            {
                printf ("'%16s' from '0x%08X' to '0x%08X' ! "
                        , SectionFilled[Cursor].name
                        , SectionFilled[Cursor].Offset
                        , SectionFilled[Cursor].Offset+SectionFilled[Cursor].Size);
                printStatus ("FAIL", FAILURE);
                printf("\n");
            }

        }
        else
        {
            for (Cursor2=0; Cursor2<SectionFilled[Cursor].Size; Cursor2+=0x4)
            {
                Status2 = ReadSection(SectionFilled[Cursor].name
                                      , FileToRead
                                      , SectionFilled[Cursor].Offset+Cursor2
                                      , 0x04
                                      , SectionFilled[Cursor].DisplayType
                                      , SectionFilled[Cursor].Check
                                      , SectionFilled[Cursor].Pattern);
                if (Status2)
                {
                    GetSection (FileToRead
                                , SectionFilled[Cursor].Offset+Cursor2
                                , 0x04
                                , SectionFilled[Cursor].DisplayType
                                , Buffer);
                    printf ("Error at '0x%08X' found :'0x%08X' ! ", SectionFilled[Cursor].Offset+Cursor2, *Buffer);
                    printStatus ("FAIL", FAILURE);
                    printf("\n");
                }
                Status3 |= Status2;
            }
            if (!Status3)
            {
                printf ("'%16s' from '0x%08X' to '0x%08X' is not empty ! "
                        , SectionFilled[Cursor].name
                        , SectionFilled[Cursor].Offset
                        , SectionFilled[Cursor].Offset+SectionFilled[Cursor].Size);
                printStatus ("GOOD", GOOD);
                printf("\n");
            }
            else
            {
                printf ("'%16s' from '0x%08X' to '0x%08X' ! "
                        , SectionFilled[Cursor].name
                        , SectionFilled[Cursor].Offset
                        , SectionFilled[Cursor].Offset+SectionFilled[Cursor].Size);
                printStatus ("FAIL", FAILURE);
                printf("\n");
            }
        }

        Cursor++;
        Status |= Status3;
        SizedCheck += SectionFilled[Cursor].Size;
    }

    *PercentCheck = SizedCheck;

exit:
    free (Buffer);
    free (metldrOffset0);
    free (bootldrOffset0);
    //free (trvk_prg0Offset0);
    //free (trvk_prg1Offset0);
    //free (trvk_pkg0Offset0);
    //free (trvk_pkg1Offset0);
    //free (ros0Offset0);
    //free (ros1Offset0);

    return Status;
}

int main(int argc, char *argv[])
{
    uint8_t  Status = EXIT_SUCCESS;
    uint8_t  GlobalStatus = EXIT_SUCCESS;
    FILE     *BinaryFile;
    uint32_t FileLength;

    uint8_t  Cursor;
    int      OptionType=0;
    struct   Options Option[NB_OPTIONS] =
    {
        {NULL, 0, 0, 0}
    };
    uint32_t ExtractionSize;
    char     DisplaySection[DATA_BUFFER_SIZE];

    uint32_t GlobalSizedCheck=0;
    uint8_t  GlobalReport[NBToReport] = {0};
    uint8_t  MD5result[MD5_DIGEST_LENGTH];

    struct Reporting ReportDetail[] =
    {
        {ReportMD5           , "MD5 Sum"              , "You can run again with option -M only"},
        {ReportExtraction    , "Section Extraction"   , "You can run again with option -E with start and size of section to try to extract"},
        {ReportStatistics    , "Statistics"           , "You can run again with option -P only"},
        {ReportGenericData   , "Generic Data Checking", "You can run again with option -G only"},
        {ReportPerConsoleData, "Per PS3 Data Checking", "You can run again with option -C only"},
        {ReportFilledArea    , "00/FF filled area"    , "You can run again with option -f only"},
        {ReportNotZero       , "Not 00 nor FF area"   , "You can run again with option -N only"},
        {ReportPerFW         , "Per Firmware data"    , "You can run again with option -F only"},
        {ReportRepetition    , "Data Repetition"      , "You can run again with option -R only"},
        {0,NULL, NULL}
    };

    if (!Win32)
    {
        GetTextDefault();
    }
    printf ("******************************\n");
    printf ("* NOR Dump Tool Version%5s *\n",  NOR_DUMP_TOOL_VERSION);
    printf ("******************************\n");
    printf ("\n\tDRAFT for 0.9.7\n");
    if ((argc < 2)||(strcmp(argv[1], "--help")==0))
    {
        printf ("\nOpen source project aimed to help to validate PS3 NOR dumps\n");
        printf ("!! This code is NOT able to give you a 100%% validation status !!\n");
        printf ("It's anyway better to do additional checking by your own,\n");
        printf ("unless the code of this tool is fully validated by experts!!!\n\n");
        printf ("Usage: %s NorFile.bin (Options)\n", argv[0]);
        printf ("Options:\n");
        printf ("  --help\t\t: Display this help.\n");
        printf ("  -v \t\t\t: Verbose for debugging purposes\n\t\t\t  A lot of data may output especially if the dump is defective\n");
        printf ("  -P \t\t\t: Give percentage of bytes\n");
        printf ("  -G \t\t\t: Check PS3 Generic information\n");
        printf ("  -C \t\t\t: Check and display perconsole information\n");
        printf ("  -f \t\t\t: Check areas filled with '00' or 'FF'\n");
        printf ("  -F \t\t\t: Check Firmware information (ros0/1 + trvk)\n");
        printf ("  -N \t\t\t: Check areas containing data in opposition to -F option\n");
        printf ("  -R \t\t\t: Check simple repetition of bytes due to stuck line\n");
        printf ("  -S FolderName \t: Split some NOR section to folder 'FolderName'\n");
        printf ("  -M Start Size \t: Run MD5 sum on file from 'Start' for 'Size' long\n");
        printf ("  -E FileName Start Size: Extract specific NOR Section from 'Start' for 'Size' long\n");
        printf ("  -D Start Size H/A \t: Display a specific NOR Section \n\t\t\t  from 'Start' for 'Size' long, use H or A for HEX or ASCII\n");
        printf ("\nBy default -P -G -C -f -F -N and -R will be applied if no option is given\n");
        printf ("\nRepo: <https://github.com/anaria28/NOR-Dump-Tool>\n");
        return EXIT_FAILURE;
    }
    char     *Buffer     = malloc(DATA_BUFFER_SIZE+1);
    char     *StuckLine  = malloc(4);
    uint32_t *SizedCheck = malloc(sizeof(uint32_t)+1);
    *SizedCheck = 0;

    if (argc==2)
    {
        OptionType = OPTION_STATS + OPTION_CHECK_GENERIC + OPTION_CHECK_PERPS3 + OPTION_CHECK_FILLED + OPTION_CHECK_NOT_ZERO + OPTION_CHECK_PER_FW + OPTION_CHECK_REPETITION;
    }

    for (Cursor=1; Cursor<argc; Cursor++)
    {
        if (strcmp(argv[Cursor], "-S")==0)
        {
            OptionType += OPTION_SPLIT;
            Option[0].Name = argv[Cursor+1];
            Option[0].Type = 1;
        }
        if (strcmp(argv[Cursor], "-M")==0)
        {
            OptionType += OPTION_MD5;
            Option[1].Start = strtol(argv[Cursor+1],NULL,0);
            Option[1].Size  = strtol(argv[Cursor+2],NULL,0);
            Option[1].Type = 1;
        }
        if (strcmp(argv[Cursor], "-E")==0)
        {
            OptionType += OPTION_EXTRACT;
            Option[2].Name  = argv[Cursor+1];
            Option[2].Start = strtol(argv[Cursor+2],NULL,0);
            Option[2].Size  = strtol(argv[Cursor+3],NULL,0);
            Option[2].Type = 1;
        }
        if (strcmp(argv[Cursor], "-P")==0)
        {
            OptionType += OPTION_STATS;
            Option[3].Type = 1;
        }
        if (strcmp(argv[Cursor], "-G")==0)
        {
            OptionType += OPTION_CHECK_GENERIC;
            Option[4].Type = 1;
        }
        if (strcmp(argv[Cursor], "-C")==0)
        {
            OptionType += OPTION_CHECK_PERPS3;
            Option[5].Type = 1;
        }
        if (strcmp(argv[Cursor], "-D")==0)
        {
            OptionType += OPTION_DISPLAY_AREA;
            Option[6].Start = strtol(argv[Cursor+1],NULL,0);
            Option[6].Size  = strtol(argv[Cursor+2],NULL,0);
            if (argc!=Cursor+3)
            {
                if (strcmp(argv[Cursor+3], "H")==0)
                    Option[6].Type = TYPE_HEX+DISPLAY_ALWAYS;
                else if (strcmp(argv[Cursor+3], "A")==0)
                    Option[6].Type = TYPE_ASCII+DISPLAY_ALWAYS;
                else
                    Option[6].Type = TYPE_HEX+DISPLAY_ALWAYS;
            }
            else
                Option[6].Type = TYPE_HEX+DISPLAY_ALWAYS;
            Option[6].Type = 1;
        }
        if (strcmp(argv[Cursor], "-f")==0)
        {
            OptionType += OPTION_CHECK_FILLED;
            Option[7].Type = 1;
        }
        if (strcmp(argv[Cursor], "-N")==0)
        {
            OptionType += OPTION_CHECK_NOT_ZERO;
            Option[8].Type = 1;
        }
        if (strcmp(argv[Cursor], "-F")==0)
        {
            OptionType += OPTION_CHECK_PER_FW;
            Option[9].Type = 1;
        }
        if (strcmp(argv[Cursor], "-R")==0)
        {
            OptionType += OPTION_CHECK_REPETITION;
            Option[10].Type = 1;
        }
        if (strcmp(argv[Cursor], "-v")==0)
        {
            Verbose = 0;
        }
    }
    NORFileName = argv[1];
    BinaryFile = fopen(NORFileName, "rb");
    if (!BinaryFile)
    {
        printf ("Failed to open %s\n", NORFileName);
        goto exit;
    }

    char * ext;
    ext = strrchr(NORFileName,'.');
    NORFileName[ext-NORFileName] = NULL;

    fseek (BinaryFile, 0, SEEK_END);
    if ((FileLength=ftell(BinaryFile))!=NOR_FILE_SIZE)
    {
        printf ("File size not correct for NOR, %d Bytes instead of %d\n", FileLength, NOR_FILE_SIZE);
        goto exit;
    }

    // Now supporting both bytes order
    if (   (ReadSection("ByteReserved? ", BinaryFile, SectionTOC[FlashStart].Offset+0x14, 0x04, TYPE_HEX, 1, "0FACE0FF")==EXIT_FAILURE)
            &&(ReadSection("ByteReserved? ", BinaryFile, SectionTOC[FlashStart].Offset+0x14, 0x04, TYPE_HEX, 1, "AC0FFFE0")==EXIT_SUCCESS))
    {
        printf("Using byte reverse method\n");
        Reverse = 0;
    }

    if (((OptionType)&(1<<0))==OPTION_SPLIT)
    {
        printf ("******************************\n");
        printf ("*     Splitting NOR Dump     *\n");
        printf ("******************************\n");

        Status = MKDIR(Option[0].Name,777);

        if (chdir(Option[0].Name))
        {
            printf ("Failed to use folder %s\n", Option[0].Name);
            goto exit;
        }
        GetSection (BinaryFile, SectionTOC[asecure_loader].Offset+0x18, 0x08, TYPE_HEX, Buffer);
        ExtractionSize = strtol(Buffer,NULL,16);
        Status |= ExtractSection("asecure_loader"  , BinaryFile, SectionTOC[asecure_loader].Offset+0x40, ExtractionSize);
        Status |= ExtractSection("eEID"            , BinaryFile, SectionTOC[eEID].Offset               , SectionTOC[eEID].Size);
        Status |= ExtractSection("cISD"            , BinaryFile, SectionTOC[cISD].Offset               , SectionTOC[cISD].Size);
        Status |= ExtractSection("cCSD"            , BinaryFile, SectionTOC[cCSD].Offset               , SectionTOC[cCSD].Size);
        Status |= ExtractSection("trvk_prg0"       , BinaryFile, SectionTOC[trvk_prg0].Offset          , SectionTOC[trvk_prg0].Size);
        Status |= ExtractSection("trvk_prg1"       , BinaryFile, SectionTOC[trvk_prg1].Offset          , SectionTOC[trvk_prg1].Size);
        Status |= ExtractSection("trvk_pkg0"       , BinaryFile, SectionTOC[trvk_pkg0].Offset          , SectionTOC[trvk_pkg0].Size);
        Status |= ExtractSection("trvk_pkg1"       , BinaryFile, SectionTOC[trvk_pkg1].Offset          , SectionTOC[trvk_pkg1].Size);
        Status |= ExtractSection("ros0"            , BinaryFile, SectionTOC[ros0].Offset               , SectionTOC[ros0].Size);
        Status |= ExtractSection("ros1"            , BinaryFile, SectionTOC[ros1].Offset               , SectionTOC[ros1].Size);
        Status |= ExtractSection("cvtrm"           , BinaryFile, SectionTOC[cvtrm].Offset              , SectionTOC[cvtrm].Size);
        Status |= ExtractSection("CELL_EXTNOR_AREA", BinaryFile, SectionTOC[CELL_EXTNOR_AREA].Offset   , SectionTOC[CELL_EXTNOR_AREA].Size);
        Status |= ExtractSection("bootldr"         , BinaryFile, SectionTOC[bootldr].Offset            , SectionTOC[bootldr].Size);
        GlobalStatus |= Status;
    }

    if (((OptionType)&(1<<1))==OPTION_MD5)
    {
        printf ("******************************\n");
        printf ("*     MD5 Sum on Section     *\n");
        printf ("******************************\n");
        printf ("Chosen section MD5 sum is: ");
        MD5SumFileSection( BinaryFile, Option[1].Start, Option[1].Size, MD5result);
        SetTextYELLOW ();
        printMD5(MD5result);
        SetTextNONE ();
        printf ("\n");
    }

    if ( ((OptionType)&(1<<2))==OPTION_EXTRACT )
    {
        printf ("******************************\n");
        printf ("*    Extracting Section      *\n");
        printf ("******************************\n");
        GlobalStatus |= ExtractSection(Option[2].Name, BinaryFile, Option[2].Start, Option[2].Size);
    }

    if (((OptionType)&(1<<3))==OPTION_STATS)
    {
        if ( Statistics (BinaryFile) )
        {
            GlobalReport[ReportStatistics] = 1;
            GlobalStatus |= 1;
        }
    }

    if (((OptionType)&(1<<4))==OPTION_CHECK_GENERIC)
    {
        if((Status = CheckGenericData(BinaryFile, SizedCheck)))
        {
            SetTextRED ();
            SetTextBOLD ();
            printf ("Some checking were not successful.\n");
            printf ("You may need to check further your dump.\n");
            printf ("But fortunately for the Generic section of the NOR it may be fixed.\n");
            SetTextNONE ();
            GlobalReport[ReportGenericData] = 1;
        }
        else
        {
            printf ("No problem found in the Generic Data, anyway remain careful!\n");
        }
        GlobalStatus |= Status;
        GlobalSizedCheck += *SizedCheck;
        *SizedCheck = 0;
    }


    if (((OptionType)&(1<<5))==OPTION_CHECK_PERPS3)
    {
        if((Status = CheckPerConsoleData(BinaryFile, SizedCheck)))
        {
            printStatus ("Some checking were not successful.\n",FAILURE);
            printStatus ("You may need to check further your dump.\n",FAILURE);
            printStatus ("Be cautious, flashing this one may lead to a brick of your PS3.\n",FAILURE);
            GlobalReport[ReportPerConsoleData] = 1;
        }
        else
        {
            printf ("No problem found in the Per Console Data, anyway remain careful!\n");
        }
        GlobalStatus |= Status;
        GlobalSizedCheck += *SizedCheck;
        *SizedCheck = 0;
    }

    if (((OptionType)&(1<<6))==OPTION_DISPLAY_AREA)
    {
        sprintf (DisplaySection, "Start at '0x%08X' of size '0x%02X'", Option[6].Start, Option[6].Size);
        Status = ReadSection(DisplaySection, BinaryFile, Option[6].Start, Option[6].Size, Option[6].Type, 0, "");
    }

    if (((OptionType)&(1<<7))==OPTION_CHECK_FILLED)
    {
        if((Status = CheckFilledData(BinaryFile, SizedCheck)))
        {
            printStatus ("Some checking were not successful.\n",WARNING);
            printStatus ("You may need to check further your dump.\n",WARNING);
            printStatus ("Be cautious there is something fishy in your dump.\n",WARNING);
            GlobalReport[ReportFilledArea] = 1;
        }
        else
        {
            printf ("No problem found in areas filled with '00' or 'FF', anyway remain careful!\n");
        }
        GlobalStatus |= Status;
        GlobalSizedCheck += *SizedCheck;
        *SizedCheck = 0;
    }

    if (((OptionType)&(1<<8))==OPTION_CHECK_NOT_ZERO)
    {
        if((Status = CheckNotZero(BinaryFile, SizedCheck)))
        {
            printStatus ("Some checking were not successful.\n",WARNING);
            printStatus ("You may need to check further your dump.\n",WARNING);
            printStatus ("Be cautious there is something fishy in your dump.\n",WARNING);
            GlobalReport[ReportNotZero] = 1;
        }
        else
        {
            printf ("There are data in supposed areas, anyway remain careful!\n");
        }
        GlobalStatus |= Status;
        GlobalSizedCheck += *SizedCheck;
        *SizedCheck = 0;
    }


    if (((OptionType)&(1<<9))==OPTION_CHECK_PER_FW)
    {
        if((Status = CheckPerFW(BinaryFile, SizedCheck)))
        {
            printStatus ("Some checking were not successful.\n",WARNING);
            printStatus ("You may need to check further your dump.\n",WARNING);
            printStatus ("Be cautious there is something fishy in your dump.\n",WARNING);
            GlobalReport[ReportPerFW] = 1;
        }
        else
        {
            printf ("No problem found in Per Firmware area careful!\n");
        }
        GlobalStatus |= Status;
        GlobalSizedCheck += *SizedCheck;
        *SizedCheck = 0;
    }


    if (((OptionType)&(1<<10))==OPTION_CHECK_REPETITION)
    {
        if((Status = CheckRepetition(BinaryFile, StuckLine)))
        {
            printStatus ("Some checking were not successful.\n",WARNING);
            printStatus ("You may need to check further your dump.\n",WARNING);
            printStatus ("Be cautious there is something fishy in your dump.\n",WARNING);
            GlobalReport[ReportRepetition] = 1;
        }
        else
        {
            printf ("No repetition found!\n");
        }
        GlobalStatus |= Status;
    }

    printf ("\n\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    printf ("\t! 0x%08X or %02.2f%% of the file has been checked !\n", GlobalSizedCheck, (double)GlobalSizedCheck*100/(double)NOR_FILE_SIZE);
    printf ("\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");

    if (GlobalStatus)
    {
        printf ("\n");
        for (Cursor=1; Cursor<NBToReport; Cursor++)
        {
            if (GlobalReport[Cursor])
            {
                SetTextRED ();
                SetTextBOLD ();
                printf ("\tError in %s\n",ReportDetail[Cursor].ReportName);
                SetTextNONE ();
                printf ("\t\t-%s\n",ReportDetail[Cursor].ReportMsg);
            }
        }
        printf ("\n");
        printf ("\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        printf ("\t!");
        printStatus(" FAIL fix it and try again", FAILURE);
        printf (" !\n");
        printf ("\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    }
    else
    {
        printf ("\n");
        for (Cursor=2; Cursor<NBToReport; Cursor++)
        {
            if (!Option[Cursor].Type)
            {
                printf ("\tFunction %s not launched\n",ReportDetail[Cursor].ReportName);
                printf ("\t\t-%s\n",ReportDetail[Cursor].ReportMsg);
            }
        }
        printf ("\n");
        printf ("\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        printf ("\t!");
        printStatus(" GOOD, same player, play again!?", GOOD);
        printf (" !\n");
        printf ("\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    }

exit:
    free (StuckLine);
    free (SizedCheck);
    free (Buffer);
    fclose (BinaryFile);

    return GlobalStatus;
}
