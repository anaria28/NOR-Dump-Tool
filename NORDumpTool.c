// Knowledge and information sources : ps3devwiki.com | ps3hax.net | your friend google
// Thanks to all people sharing their findings and knowledge!
//
// Aim of this code:
// - Check as much as possible a NOR dump in order to validate it
// - Run some statistics on the dump (% of '00' 'FF' ...)
// - Extract some specific console information (S/N, MAC, and so on)
//
// Versions :
// 0.9.x Increased checking of area filled with unique byte(s) + percentage indicator and global status + part of Fixed & Cleaned from an0nym0u5
// 0.9.5 Increased portability to Windows via MinGW32
// 0.9.4 Fixed stupid mistake in ReadSection() (Thx @Sarah1331)
// 0.9.3 Added checking of area filled with unique byte(s) e.g. in flash format: 0x210 -> 0x3FF : full of FF
// 0.9.2 memory allocation fix (Thx @judges) in CheckPerConsoleData() + fixed wrong English (mixed French...) in main()
// 0.9.1 Added -D option to display a specific section in HEX or ASCII
// 0.9.0 First public release

#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/md5.h>

#ifdef __MINGW32__
// for windows
#define MKDIR(x,y) mkdir(x)
#else
// for the real world
#define MKDIR(x,y) mkdir(x,y)
#endif

#define TYPE_HEX              0x00
#define TYPE_ASCII            0x01
#define DISPLAY_ALWAYS        0x02
#define DISPLAY_FAIL          0x04
#define DISPLAY_GOOD          0x08

#define NB_OPTIONS            8

#define OPTION_SPLIT          0x01
#define OPTION_MD5            0x02
#define OPTION_EXTRACT        0x04
#define OPTION_STATS          0x08
#define OPTION_CHECK_GENERIC  0x10
#define OPTION_CHECK_PERPS3   0x20
#define OPTION_DISPLAY_AREA   0x40
#define OPTION_CHECK_FILLED   0x80

#define NOR_FILE_SIZE         0x1000000
#define DATA_BUFFER_SIZE      0x100

#define MIN00                 3083652
#define MAX00                 4867070
#define MINFF                 1748186
#define MAXFF                 1758252
#define MAXOTHERS             83886

enum TOCnames {
    asecure_loader = 0,
    eEID,
    cISD,
    cCSD,
    trvk_prg0,
    trvk_prg1,
    trvk_pkg0,
    trvk_pkg1,
    ros0,
    ros1,
    cvtrm,
    CELL_EXTNOR_AREA,
    bootldr,
    FlashStart,
    FlashFormat,
    FlashRegion,
    TotalSections
};

struct Options {
    char       *Name;
    int        Type;
    uint32_t   Start;
    uint32_t   Size;
};

struct Sections {
    char       *name;
    uint32_t   Offset;
    uint32_t   Size;
    int        DisplayType;
    int        Check;
    char       *Pattern;
};

static struct Sections SectionTOC[] = {
    { "asecure_loader",   0x000800, 0x02E800, 0, 0, NULL },
    { "eEID",             0x02F000, 0x010000, 0, 0, NULL },
    { "cISD",             0x03F000, 0x0800,   0, 0, NULL },
    { "cCSD",             0x03F800, 0x0800,   0, 0, NULL },
    { "trvk_prg0",        0x040000, 0x020000, 0, 0, NULL },
    { "trvk_prg1",        0x060000, 0x020000, 0, 0, NULL },
    { "trvk_pkg0",        0x080000, 0x020000, 0, 0, NULL },
    { "trvk_pkg1",        0x0A0000, 0x020000, 0, 0, NULL },
    { "ros0",             0x0C0000, 0x700000, 0, 0, NULL },
    { "ros1",             0x7C0000, 0x700000, 0, 0, NULL },
    { "cvtrm",            0xEC0000, 0x040000, 0, 0, NULL },
    { "CELL_EXTNOR_AREA", 0xF20000, 0x020000, 0, 0, NULL },
    { "bootldr",          0xFC0000, 0x040000, 0, 0, NULL },
    { "FlashStart",       0x000000, 0x0200,   0, 0, NULL },
    { "FlashFormat",      0x000200, 0x0200,   0, 0, NULL },
    { "FlashRegion",      0x000400, 0x0400,   0, 0, NULL },
    { NULL, 0, 0, 0, 0, NULL }
};

struct IndividualSystemData{
    char *IDPSTargetID;     // 0x02F077 (NOR) 0x80877 (NAND)
    char *SKU;              //
    char *metldrOffset0;    // 0x081E (NOR) 0x4081E (NAND)
    char *metldrOffset1;    // 0x0842 (NOR) 0x40842 (NAND)
    uint32_t bootldrSize;
    char *bootldrOffset0;   // 0xFC0002 (NOR) 0x02 (NAND)
    char *bootldrOffset1;   // 0xFC0012 (NOR) 0x12 (NAND)
    char *MinFW;
};

static struct IndividualSystemData CheckPerSKU[] = {
    { "01", "DEH-Z1010",                                       "1420", "113E", 0x2D020, "2CFE", "2CFE", "<= 0.80.004" },
    { "01", "DECR-1000",                                       "EC40", "0EC0", 0x2A840, "2A7F", "2A7F", "<= 0.85.009" },
    { "01", "DEH-H1001-D?",                                    "EC40", "0EC0", 0x2A830, "2A7F", "2A7F", "<= 0.85.009" },
    { "01", "DEH-H1000A-E (COK-001) DEX",                      "EC70", "0EC3", 0x2A1E0, "2A1A", "2A1A", "< 095.001" },
    { "01", "CECHAxx (COK-001)",                               "EE10", "0EDD", 0x2A430, "2A3F", "2A3F", "1" },
    { "01", "CECHAxx (COK-001) factory FW 1.00",               "EDA0", "0ED6", 0x2A2E0, "2A2A", "2A2A", "1" },
    { "01", "CECHAxx (COK-001)",                               "EDE0", "0EDA", 0x2A3B0, "2A37", "2A37", "1" },
    { "01", "DECHAxx (COK-001) DEX",                           "EDA0", "0ED6", 0x2A2E0, "2A2A", "2A2A", "1" },
    { "02", "CECHBxx (COK-001)",                               "EDA0", "0ED6", 0x2A2E0, "2A2A", "2A2A", "1" },
    { "03", "CECHCxx (COK-002)",                               "EDA0", "0ED6", 0x2A2E0, "2A2A", "2A2A", "1" },
    { "03", "CECHCxx (COK-002) factory FW 1.00",               "EBF0", "0EBB", 0x30480, "3044", "3044", "1" },
    { "03", "CECHCxx (COK-002)",                               "EDE0", "0EDA", 0x2A3B0, "2A37", "2A37", "1" },
    { "03", "CECHExx (COK-002)",                               "EA60", "0EA2", 0x2EE70, "2EE3", "2EE3", NULL },
    { "04", "Namco System 357 (COK-002) ARC",                  "E7B0", "0E77", 0x2E900, "2E8C", "2E8C", "1.90?" },
    { "04", "CECHExx (COK-002)",                               "EE10", "0EDD", 0x2A430, "2A3F", "2A3F", "1" },
    { "05", "CECHGxx (SEM-001)",                               "E7B0", "0E77", 0x2E900, "2E8C", "2E8C", "1.9" },
    { "05", "CECHGxx (SEM-001)",                               "E7B0", "0E77", 0x2F200, "2F1C", "2F1C", "2.3" },
    { "05", "CECHGxx (SEM-001)",                               "E8C0", "0E88", 0x2EF80, "2EF4", "2EF4", "2.3" },
    { "06", "CECHHxx (DIA-001)",                               "E7B0", "0E77", 0x2F200, "2F1C", "2F1C", "2.3" },
    { "06", "CECHHxx (DIA-001)",                               "E8C0", "0E88", 0x2EF80, "2EF4", "2EF4", "2.3" },
    { "06", "CECHHxx (DIA-001)",                               "E8E0", "0E8A", 0x2EF80, "2EF4", "2EF4", "1.97" },
    { "06", "CECHHxx (DIA-001)",                               "EA60", "0EA2", 0x2EE70, "2EE3", "2EE3", "1.97" },
    { "06", "CECHMxx (DIA-001)",                               "EA60", "0EA2", 0x2EE70, "2EE3", "2EE3", "1.97" },
    { "07", "CECHJxx (DIA-002) factory FW 2.30 - datecode 8B", "E8E0", "0E8A", 0x2EF80, "2EF4", "2EF4", "2.3" },
    { "07", "CECHJxx (DIA-002)",                               "EA60", "0EA2", 0x2EE70, "2EE3", "2EE3", "2.3" },
    { "07", "CECHKxx (DIA-002) datecode 8C",                   "EA60", "0EA2", 0x2EE70, "2EE3", "2EE3", "2.3" },
    { "07", "DECHJxx (DIA-002) DEX",                           "E8D0", "0E89", 0x2EAF0, "2EAB", "2EAB", "2.16" },
    { "08", "Namco System 357 (VER-001) ARC",                  "E8D0", "0E89", 0x2EAF0, "2EAB", "2EAB", "2.45?" },
    { "08", "CECHLxx/CECHPxx (VER-001) ",                      "E8D0", "0E89", 0x2EAF0, "2EAB", "2EAB", "2.45" },
    { "08", "CECHLxx (VER-001)",                               "E8D0", "0E89", 0x2EB70, "2EB3", "2EB3", "2.45" },
    { "08", "CECHLxx (VER-001) factory FW 2.30",               "E890", "0E85", 0x2F170, "2F13", "2F13", "2.3" },
    { "09", "CECH-20xx (DYN-001) factory FW 2.76",             "E890", "0E85", 0x2F170, "2F13", "2F13", "2.7" },
    { "09", "DECR-1400 (DEB-001) DECR factory FW 2.60",        "E890", "0E85", 0x2F170, "2F13", "2F13", "2.6" },
    { "09", "CECH-20xx (DYN-001)",                             "E920", "0E8E", 0x2F3F0, "2F3B", "2F3B", "2.7" },
    { "0A", "CECH-21xx (SUR-001)",                             "E920", "0E8E", 0x2F4F0, "2F4B", "2F4B", "3.2" },
    { "0B", "CECH-25xx (JTP-001) factory FW 3.40 datecode 0C", "E920", "0E8E", 0x2F4F0, "2F4B", "2F4B", "3.4" },
    { "0B", "CECH-25xx (JSD-001) factory FW 3.41 datecode 0C", "E920", "0E8E", 0x2F4F0, "2F4B", "2F4B", "3.4" },
    { "0B", "CECH-25xx (JSD-001) factory FW 3.56 datecode 0D", "E960", "0E92", 0x2F570, "2F53", "2F53", "3.5" },
    { "0B", "CECH-25xx (JTP-001) factory FW 3.56 datecode 1A", "E960", "0E92", 0x2F570, "2F53", "2F53", "3.5" },
    { "0B", "CECH-25xx (JTP-001) factory FW 3.56 datecode 1A", "E960", "0E92", 0x2F5F0, "2F5B", "2F5B", "3.56" },
    { "0B", "CECH-25xx (JSD-001) factory FW 3.56 datecode 1B", "E960", "0E92", 0x2F5F0, "2F5B", "2F5B", "3.56" },
    { "0B", "CECH-25xx (JTP-001) factory FW 3.56 datecode 1B", "E960", "0E92", 0x2F5F0, "2F5B", "2F5B", "3.56" },
    { "0B", "CECH-25xx (JSD-001) factory FW 3.60 datecode 1B", "F920", "0F8E", 0x2FFF0, "2FFB", "2FFB", "3.6" },
    { "0B", "CECH-25xx (JTP-001) factory FW 3.60",             "F920", "0F8E", 0x2FFF0, "2FFB", "2FFB", "3.6" },
    { "0C", "CECH-30xx (KTE-001) factory FW 3.65",             "F920", "0F8E", 0x2FFF0, "2FFB", "2FFB", "3.6" },
    { "0D", "CECH-40xx (MSX-001 or MPX-001)",                  "F9B0", "0F97", 0x301F0, "301B", "301B", "4.20" },
    { NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL}
};

enum ReportChecking {
    ReportMD5 = 0,
    ReportExtraction,
    ReportStatistics,
    ReportGenericData,
    ReportPerConsoleData,
    ReportFilledArea,
    NBToReport
};

struct Reporting {
    uint8_t ReportNumber;
    char *ReportName;
    char *ReportMsg;
};

void MD5SumFileSection(char* SectionText, FILE *FileToRead, uint32_t Position, uint32_t Size) {
    unsigned char MD5Sum[MD5_DIGEST_LENGTH];
    int ByteSize;
    uint32_t Cursor;
    int DataWidth = 0x10;
    unsigned char DataValue[DataWidth];
    MD5_CTX mdContext;

    MD5_Init (&mdContext);

    fseek(FileToRead, Position, SEEK_SET);
    for (Cursor=0;Cursor<NOR_FILE_SIZE;Cursor+=DataWidth) {
        ByteSize = fread (DataValue, 1, DataWidth, FileToRead);
        MD5_Update (&mdContext, DataValue, ByteSize);
    }

    MD5_Final (MD5Sum,&mdContext);

    printf ("%s", SectionText);
    for(Cursor = 0; Cursor < MD5_DIGEST_LENGTH; Cursor++)
        printf("%02x", MD5Sum[Cursor]);

    printf("\n");
}

uint8_t ExtractSection(char* SectionName, FILE *FileToRead, uint32_t Position, uint32_t Size) {
    uint32_t Cursor;
    char *Buffer;
    FILE *BinaryFile;

    BinaryFile = fopen(SectionName, "wb");
    if (!BinaryFile) {
        printf("Failed to open %s\n", SectionName);
        return EXIT_FAILURE;
    }

    fseek(FileToRead, Position, SEEK_SET);

    if((Buffer = malloc(Size + 1)))
        fread(Buffer, Size, 1, FileToRead);

    for (Cursor=0;Cursor<Size;Cursor++)
        fputc(Buffer[Cursor], BinaryFile);

    printf("Extraction done for %s\n", SectionName);
    fclose(BinaryFile);
    free(Buffer);
    return EXIT_SUCCESS;
}

uint8_t Statistics(FILE *FileToRead) {
    // Calculate some statistics on bytes percentages
    uint8_t Status=EXIT_SUCCESS;
    uint32_t Cursor;
    uint16_t Counter;
    uint32_t CountOthers=0;
    uint32_t CountByte[0xFF+1];

    char msg_low[]  = "Too Low";
    char msg_high[] = "Too High";
    char msg_good[] = "Good";
    
    char *Status00=NULL;
    char *StatusFF=NULL;
    char *StatusOthers=NULL;

    printf("******************************\n");
    printf("*         Statistics         *\n");
    printf("******************************\n");

    fseek(FileToRead, 0, SEEK_SET);

    for (Counter=0x00;Counter<0xFF+1;Counter++)
        CountByte[Counter]=0;

    for (Cursor=0;Cursor<NOR_FILE_SIZE;Cursor++)
        CountByte[fgetc(FileToRead)]+=1;

    for (Counter=0x01;Counter<0xFF;Counter++) {
        if (CountOthers<CountByte[Counter])
            CountOthers=CountByte[Counter];
    }

    if (CountByte[0x00]<MIN00) {
        Status00=msg_low;
        Status = EXIT_FAILURE;
    }
    else if (CountByte[0x00]>MAX00) {
        Status00=msg_high;
        Status = EXIT_FAILURE;
    }
    else
        Status00=msg_good;

    if (CountByte[0xFF]<MINFF) {
        StatusFF=msg_low;
        Status = EXIT_FAILURE;
    }
    else if (CountByte[0xFF]>MAXFF) {
        StatusFF=msg_high;
        Status = EXIT_FAILURE;
    }
    else
        StatusFF=msg_good;

    if (CountOthers>MAXOTHERS) {
        StatusOthers=msg_high;
        Status = EXIT_FAILURE;
    }
    else
        StatusOthers=msg_good;

    printf ("Bytes '00' found %d times, %2.2f%% %s\n",          CountByte[0x00], (double)CountByte[0x00]*100/(double)NOR_FILE_SIZE, Status00);
    printf ("Bytes 'FF' found %d times, %2.2f%% %s\n",          CountByte[0xFF], (double)CountByte[0xFF]*100/(double)NOR_FILE_SIZE, StatusFF);
    printf ("Other bytes found %d times maximum, %2.2f%% %s\n", CountOthers,     (double)CountOthers    *100/(double)NOR_FILE_SIZE, StatusOthers);
    
    return Status;
}

void GetSection(FILE *FileToRead, uint32_t Position, uint8_t Size, uint8_t DisplayType, char *section_data) {
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

    if (((DisplayType)&(1<<0))==TYPE_HEX) {
        for (Cursor=0;Cursor<Size;Cursor++){
            sprintf(section_data, "%s%02X", section_data, fgetc(FileToRead));
        }
    }

    else if (((DisplayType)&(1<<0))==TYPE_ASCII) {
        fread(section_data, Size, 1, FileToRead);
        section_data[Size]=NULL;
    }
}

uint8_t ReadSection(char *SectionName, FILE *FileToRead, uint32_t Position, uint8_t Size, uint8_t DisplayType, uint8_t CheckFlag, char *CheckPattern) {
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
    char DisplaySection[0x100]={0};

    fseek(FileToRead, Position, SEEK_SET);

    for (Cursor=0;Cursor<Size;Cursor++)    {
        if (((DisplayType)&(1<<0))==TYPE_HEX)
            sprintf(DisplaySection, "%s%02X", DisplaySection,fgetc(FileToRead));

        else if (((DisplayType)&(1<<0))==TYPE_ASCII)
            sprintf(DisplaySection, "%s%c", DisplaySection,fgetc(FileToRead));
    }

    if (((DisplayType)&(1<<1))==DISPLAY_ALWAYS)
        printf ("Section: %s: read %s \n", SectionName, DisplaySection);

    if (CheckFlag) {
        for (Cursor=0;Cursor<Size;Cursor++) {
            if (((DisplayType)&(1<<0))==TYPE_ASCII) {
                if (DisplaySection[Cursor]!=CheckPattern[Cursor]) {
                    Status=EXIT_FAILURE;
                    if (((DisplayType)&(1<<2))==DISPLAY_FAIL)
                        printf ("Section: %s: read '%s' !   mismatch pattern '%s' ! <- IT FAILS HERE\n", SectionName, DisplaySection, CheckPattern);
                    return Status;
                }
                else {
                    if (((DisplayType)&(1<<3))==DISPLAY_GOOD)
                        printf ("Section: %s: read '%s' !   match pattern '%s'\n", SectionName, DisplaySection, CheckPattern);
                }
            }
            else if (((DisplayType)&(1<<0))==TYPE_HEX) {
                if ((DisplaySection[Cursor*2]!=CheckPattern[Cursor*2])||(DisplaySection[Cursor*2+1]!=CheckPattern[Cursor*2+1])) {
                    Status=EXIT_FAILURE;
                    if (((DisplayType)&(1<<2))==DISPLAY_FAIL)
                        printf ("Section: %s: read '%s' !   mismatch pattern '%s' !\n", SectionName, DisplaySection, CheckPattern);
                    return Status;
                }
                else {
                    if (((DisplayType)&(1<<3))==DISPLAY_GOOD)
                        printf ("Section: %s: read '%s' !   match pattern '%s'\n", SectionName, DisplaySection, CheckPattern);
                }
            }
        }
    }
    return Status;
}

uint8_t CheckGenericData(FILE *FileToRead, uint32_t *PercentCheck) {
    int Cursor=0;
    uint8_t Status=EXIT_SUCCESS;
    uint32_t SizedCheck=0;
    struct Sections SectionGenericData[] = {
        {"Flash Magic Number     ", SectionTOC[FlashStart].Offset+0x10   , 0x10, TYPE_HEX  +DISPLAY_FAIL, 1, "000000000FACE0FF00000000DEADBEEF"},
        {"Flash Format Type      ", SectionTOC[FlashFormat].Offset       , 0x10, TYPE_HEX  +DISPLAY_FAIL, 1, "49464900000000010000000200000000"},
        {"FlashRegion Unkown     ", SectionTOC[FlashRegion].Offset       , 0x04, TYPE_HEX  +DISPLAY_FAIL, 1, "00000001"},
        {"FlashRegion Entry Count", SectionTOC[FlashRegion].Offset+0x0004, 0x04, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000B"},
        {"FlashRegion Length     ", SectionTOC[FlashRegion].Offset+0x0008, 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000EFFC00"},
        {"FlashRegion  1 offset  ", SectionTOC[FlashRegion].Offset+0x0010, 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000000400"},
        {"FlashRegion  1 length  ", SectionTOC[FlashRegion].Offset+0x0018, 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "000000000002E800"},
        {"FlashRegion  1 name    ", SectionTOC[FlashRegion].Offset+0x0020, 0x0E, TYPE_ASCII+DISPLAY_FAIL, 1, "asecure_loader"},
        {"FlashRegion  1 NULL    ", SectionTOC[FlashRegion].Offset+0x002E, 0x12, TYPE_HEX  +DISPLAY_FAIL, 1, "000000000000000000000000000000000000"},
        {"FlashRegion  2 offset  ", SectionTOC[FlashRegion].Offset+0x0040, 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "000000000002EC00"},
        {"FlashRegion  2 length  ", SectionTOC[FlashRegion].Offset+0x0048, 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000010000"},
        {"FlashRegion  2 name    ", SectionTOC[FlashRegion].Offset+0x0050, 0x04, TYPE_ASCII+DISPLAY_FAIL, 1, "eEID"},
        {"FlashRegion  2 NULL    ", SectionTOC[FlashRegion].Offset+0x0054, 0x1c, TYPE_HEX  +DISPLAY_FAIL, 1, "00000000000000000000000000000000000000000000000000000000"},
        {"FlashRegion  3 offset  ", SectionTOC[FlashRegion].Offset+0x0070, 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "000000000003EC00"},
        {"FlashRegion  3 length  ", SectionTOC[FlashRegion].Offset+0x0078, 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000000800"},
        {"FlashRegion  3 name    ", SectionTOC[FlashRegion].Offset+0x0080, 0x04, TYPE_ASCII+DISPLAY_FAIL, 1, "cISD"},
        {"FlashRegion  3 NULL    ", SectionTOC[FlashRegion].Offset+0x0084, 0x1c, TYPE_HEX  +DISPLAY_FAIL, 1, "00000000000000000000000000000000000000000000000000000000"},
        {"FlashRegion  4 offset  ", SectionTOC[FlashRegion].Offset+0x00A0, 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "000000000003F400"},
        {"FlashRegion  4 length  ", SectionTOC[FlashRegion].Offset+0x00A8, 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000000800"},
        {"FlashRegion  4 name    ", SectionTOC[FlashRegion].Offset+0x00B0, 0x04, TYPE_ASCII+DISPLAY_FAIL, 1, "cCSD"},
        {"FlashRegion  4 NULL    ", SectionTOC[FlashRegion].Offset+0x00B4, 0x1c, TYPE_HEX  +DISPLAY_FAIL, 1, "00000000000000000000000000000000000000000000000000000000"},
        {"FlashRegion  5 offset  ", SectionTOC[FlashRegion].Offset+0x00D0, 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "000000000003FC00"},
        {"FlashRegion  5 length  ", SectionTOC[FlashRegion].Offset+0x00D8, 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000020000"},
        {"FlashRegion  5 name    ", SectionTOC[FlashRegion].Offset+0x00E0, 0x09, TYPE_ASCII+DISPLAY_FAIL, 1, "trvk_prg0"},
        {"FlashRegion  5 NULL    ", SectionTOC[FlashRegion].Offset+0x00E9, 0x17, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000000000000000000000000000000000000000"},
        {"FlashRegion  6 offset  ", SectionTOC[FlashRegion].Offset+0x0100, 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "000000000005FC00"},
        {"FlashRegion  6 length  ", SectionTOC[FlashRegion].Offset+0x0108, 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000020000"},
        {"FlashRegion  6 name    ", SectionTOC[FlashRegion].Offset+0x0110, 0x09, TYPE_ASCII+DISPLAY_FAIL, 1, "trvk_prg1"},
        {"FlashRegion  6 NULL    ", SectionTOC[FlashRegion].Offset+0x0119, 0x17, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000000000000000000000000000000000000000"},
        {"FlashRegion  7 offset  ", SectionTOC[FlashRegion].Offset+0x0130, 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "000000000007FC00"},
        {"FlashRegion  7 length  ", SectionTOC[FlashRegion].Offset+0x0138, 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000020000"},
        {"FlashRegion  7 name    ", SectionTOC[FlashRegion].Offset+0x0140, 0x09, TYPE_ASCII+DISPLAY_FAIL, 1, "trvk_pkg0"},
        {"FlashRegion  7 NULL    ", SectionTOC[FlashRegion].Offset+0x0149, 0x17, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000000000000000000000000000000000000000"},
        {"FlashRegion  8 offset  ", SectionTOC[FlashRegion].Offset+0x0160, 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "000000000009FC00"},
        {"FlashRegion  8 length  ", SectionTOC[FlashRegion].Offset+0x0168, 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000020000"},
        {"FlashRegion  8 name    ", SectionTOC[FlashRegion].Offset+0x0170, 0x09, TYPE_ASCII+DISPLAY_FAIL, 1, "trvk_pkg1"},
        {"FlashRegion  8 NULL    ", SectionTOC[FlashRegion].Offset+0x0179, 0x17, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000000000000000000000000000000000000000"},
        {"FlashRegion  9 offset  ", SectionTOC[FlashRegion].Offset+0x0190, 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "00000000000BFC00"},
        {"FlashRegion  9 length  ", SectionTOC[FlashRegion].Offset+0x0198, 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000700000"},
        {"FlashRegion  9 name    ", SectionTOC[FlashRegion].Offset+0x01A0, 0x04, TYPE_ASCII+DISPLAY_FAIL, 1, "ros0"},
        {"FlashRegion  9 NULL    ", SectionTOC[FlashRegion].Offset+0x01A4, 0x1c, TYPE_HEX  +DISPLAY_FAIL, 1, "00000000000000000000000000000000000000000000000000000000"},
        {"FlashRegion 10 offset  ", SectionTOC[FlashRegion].Offset+0x01C0, 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "00000000007BFC00"},
        {"FlashRegion 10 length  ", SectionTOC[FlashRegion].Offset+0x01C8, 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000700000"},
        {"FlashRegion 10 name    ", SectionTOC[FlashRegion].Offset+0x01D0, 0x04, TYPE_ASCII+DISPLAY_FAIL, 1, "ros1"},
        {"FlashRegion 10 NULL    ", SectionTOC[FlashRegion].Offset+0x01D4, 0x1c, TYPE_HEX  +DISPLAY_FAIL, 1, "00000000000000000000000000000000000000000000000000000000"},
        {"FlashRegion 11 offset  ", SectionTOC[FlashRegion].Offset+0x01F0, 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000EBFC00"},
        {"FlashRegion 11 length  ", SectionTOC[FlashRegion].Offset+0x01F8, 0x08, TYPE_HEX  +DISPLAY_FAIL, 1, "0000000000040000"},
        {"FlashRegion 11 name    ", SectionTOC[FlashRegion].Offset+0x0200, 0x05, TYPE_ASCII+DISPLAY_FAIL, 1, "cvtrm"},
        {"FlashRegion 11 NULL    ", SectionTOC[FlashRegion].Offset+0x0205, 0x1b, TYPE_HEX  +DISPLAY_FAIL, 1, "000000000000000000000000000000000000000000000000000000"},
        {NULL, 0, 0, 0, 0, NULL}
    };

    printf("******************************\n");
    printf("*        Generic Data        *\n");
    printf("******************************\n");
    while (SectionGenericData[Cursor].name!=NULL) {
        Status |= ReadSection(SectionGenericData[Cursor].name
                            , FileToRead
                            , SectionGenericData[Cursor].Offset
                            , SectionGenericData[Cursor].Size
                            , SectionGenericData[Cursor].DisplayType
                            , SectionGenericData[Cursor].Check
                            , SectionGenericData[Cursor].Pattern);
        SizedCheck = SizedCheck + SectionGenericData[Cursor].Size;
        Cursor++;
    }

    *PercentCheck = SizedCheck;
    return Status;
}

uint8_t CheckPerConsoleData(FILE *FileToRead, uint32_t *PercentCheck) {
    int Cursor=0;
    int SKUFound=0;
    uint8_t Status=EXIT_SUCCESS;
    char *Buffer;
    uint32_t SizedCheck=0;

    char *IDPSTargetID;
    char *metldrOffset0;
    char *metldrOffset1;
    char *bootldrOffset0;
    char *bootldrOffset1;

    Buffer = malloc(DATA_BUFFER_SIZE);
    IDPSTargetID = malloc(3);
    metldrOffset0  = malloc(5);
    metldrOffset1  = malloc(5);
    bootldrOffset0  = malloc(5);
    bootldrOffset1  = malloc(5);

    struct Sections SectionPerConsole[] = {
        {"mtldr size and rev ", SectionTOC[asecure_loader].Offset+0x40   , 0x10, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"mtldr size and pcn ", SectionTOC[asecure_loader].Offset+0x50   , 0x10, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"EID0  -       IDPS ", SectionTOC[eEID].Offset+0x70             , 0x10, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"EID0 static        ", SectionTOC[eEID].Offset+0x80             , 0x04, TYPE_HEX  +DISPLAY_ALWAYS, 1, "0012000B"},
        {"EID0 pcn           ", SectionTOC[eEID].Offset+0x84             , 0x0B, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"EID3  - ckp_mgt_id ", SectionTOC[eEID].Offset+0x12A8           , 0x08, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"EID3 static        ", SectionTOC[eEID].Offset+0x12B0           , 0x04, TYPE_HEX  +DISPLAY_ALWAYS, 1, "000100D0"},
        {"EID3 pcn           ", SectionTOC[eEID].Offset+0x12B4           , 0x0B, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"EID5  -       IDPS ", SectionTOC[eEID].Offset+0x13D0           , 0x10, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"EID5 static        ", SectionTOC[eEID].Offset+0x13E0           , 0x04, TYPE_HEX  +DISPLAY_ALWAYS, 1, "00120730"},
        {"EID5 pcn           ", SectionTOC[eEID].Offset+0x13E4           , 0x0B, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"PS3 MAC Address    ", SectionTOC[cISD].Offset+0x40             , 0x06, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"cISD1 Magic Number ", SectionTOC[cISD].Offset+0x60             , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "7F49444C"},
        {"cISD1 -        CID ", SectionTOC[cISD].Offset+0x6C             , 0x04, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"cISD1 -       eCID ", SectionTOC[cISD].Offset+0x70             , 0x20, TYPE_ASCII+DISPLAY_ALWAYS, 0, NULL},
        {"cISD1 -   board_id ", SectionTOC[cISD].Offset+0x90             , 0x08, TYPE_ASCII+DISPLAY_ALWAYS, 0, NULL},
        {"cISD1 -   kiban_id ", SectionTOC[cISD].Offset+0x98             , 0x0c, TYPE_ASCII+DISPLAY_ALWAYS, 0, NULL},
        {"cISD1 -0x3F0A4 Data", SectionTOC[cISD].Offset+0xA4             , 0x06, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"cISD1 -0x3F0B0 Data", SectionTOC[cISD].Offset+0xB0             , 0x08, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"cISD1 - ckp_mgt_id ", SectionTOC[cISD].Offset+0xB8             , 0x08, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"cvtrm - pck/puk    ", SectionTOC[cvtrm].Offset+0x1D748         , 0x14, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"HDD information    ", SectionTOC[CELL_EXTNOR_AREA].Offset+0x204, 0x1C, TYPE_ASCII+DISPLAY_ALWAYS, 0, NULL},
        {"PS3 Serial Number  ", SectionTOC[CELL_EXTNOR_AREA].Offset+0x230, 0x10, TYPE_ASCII+DISPLAY_ALWAYS, 0, NULL},
        {"Bootldr hdr and rev", SectionTOC[bootldr].Offset               , 0x10, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"Bootldr hdr and pcn", SectionTOC[bootldr].Offset+0x10          , 0x10, TYPE_HEX  +DISPLAY_ALWAYS, 0, NULL},
        {"cvtrm SCEI magicnbr", SectionTOC[cvtrm].Offset                 , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "53434549"},
        {"cvtrm hdr          ", SectionTOC[cvtrm].Offset+0x004004        , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "5654524D"},
        {"cvtrm hdr bis      ", SectionTOC[cvtrm].Offset+0x024004        , 0x04, TYPE_HEX  +DISPLAY_FAIL  , 1, "5654524D"},
        {NULL, 0, 0, 0, 0, NULL}
    };

    printf("******************************\n");
    printf("*      Per Console Data      *\n");
    printf("******************************\n");

    while (SectionPerConsole[Cursor].name!=NULL) {
        Status |= ReadSection(SectionPerConsole[Cursor].name
                            , FileToRead
                            , SectionPerConsole[Cursor].Offset
                            , SectionPerConsole[Cursor].Size
                            , SectionPerConsole[Cursor].DisplayType
                            , SectionPerConsole[Cursor].Check
                            , SectionPerConsole[Cursor].Pattern);
        SizedCheck = SizedCheck + SectionPerConsole[Cursor].Size;
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
    
    Cursor=0;
    while (CheckPerSKU[Cursor].IDPSTargetID!=NULL) {
        if ((strcmp(CheckPerSKU[Cursor].IDPSTargetID,IDPSTargetID)==0)
            &&(strcmp(CheckPerSKU[Cursor].metldrOffset0,metldrOffset0)==0)
            &&(strcmp(CheckPerSKU[Cursor].metldrOffset1,metldrOffset1)==0)
            &&(strcmp(CheckPerSKU[Cursor].bootldrOffset0,bootldrOffset0)==0)
            &&(strcmp(CheckPerSKU[Cursor].bootldrOffset1,bootldrOffset1)==0)) {
            printf("PS3 SKU : %s minimum FW : %s (item %d in list)\n", CheckPerSKU[Cursor].SKU, CheckPerSKU[Cursor].MinFW, Cursor);
            SKUFound=1;
        }
        Cursor++;
    }

    if (!SKUFound){
        printf("Data found in NOR to identify the SKU are:\n- TargetID:'%s'\n", IDPSTargetID);
        printf("- metldr Offset 0:'%s'\n", metldrOffset0);
        printf("- metldr Offset 1:'%s'\n", metldrOffset1);
        printf("- bootldr Offset 0:'%s'\n", bootldrOffset0);
        printf("- bootldr Offset 1:'%s'\n", bootldrOffset1);
    }
    *PercentCheck = SizedCheck;

    free(IDPSTargetID);
    free(metldrOffset0);
    free(metldrOffset1);
    free(bootldrOffset0);
    free(bootldrOffset1);
    free(Buffer);
    return Status;
}

uint8_t CheckFilledData (FILE *FileToRead, uint32_t *PercentCheck){
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

    char *Buffer= malloc(DATA_BUFFER_SIZE);

    char *metldrOffset0    = malloc(5);;
    char *bootldrOffset0   = malloc(5);;
    char *trvk_prg0Offset0 = malloc(5);;
    char *trvk_prg1Offset0 = malloc(5);;
    char *trvk_pkg0Offset0 = malloc(5);;
    char *trvk_pkg1Offset0 = malloc(5);;
    //    char *ros0Offset0= malloc(5);;
    //    char *ros1Offset0= malloc(5);;

    printf("******************************\n");
    printf("* Area filled with 00 or FF  *\n");
    printf("******************************\n");

    GetSection(FileToRead, SectionTOC[asecure_loader].Offset+0x42, 0x02, TYPE_HEX, metldrOffset0);    
    metldrSize = (strtol(metldrOffset0,NULL,16))*0x10+0x40;
    metldrFilledSize = SectionTOC[eEID].Offset - metldrSize - SectionTOC[asecure_loader].Offset - 0x40;

    GetSection(FileToRead, SectionTOC[bootldr].Offset+0x02, 0x02, TYPE_HEX, bootldrOffset0);    
    bootldrSize = (strtol(bootldrOffset0,NULL,16))*0x10+0x40;
    bootldrFilledSize = 0x1000000 - bootldrSize - SectionTOC[bootldr].Offset;

    GetSection(FileToRead, SectionTOC[trvk_prg0].Offset+0x0E, 0x02, TYPE_HEX, trvk_prg0Offset0);
    trvk_prg0Size = strtol(trvk_prg0Offset0,NULL,16);
    trvk_prg0FilledSize = 0x040FF0 - trvk_prg0Size - SectionTOC[trvk_prg0].Offset - 0x10;
    //printf("debug: trvk_prg0Size:'0x%08X' trvk_prg0FilledSize:'0x%08X' \n",trvk_prg0Size,trvk_prg0FilledSize);
    
    GetSection(FileToRead, SectionTOC[trvk_prg1].Offset+0x0E, 0x02, TYPE_HEX, trvk_prg1Offset0);
    trvk_prg1Size = strtol(trvk_prg1Offset0,NULL,16);
    trvk_prg1FilledSize = 0x060FF0 - trvk_prg1Size - SectionTOC[trvk_prg1].Offset - 0x10;
    //printf("debug: trvk_prg1Size:'0x%08X' trvk_prg1FilledSize:'0x%08X' \n",trvk_prg1Size,trvk_prg1FilledSize);
    
    GetSection(FileToRead, SectionTOC[trvk_pkg0].Offset+0x0E, 0x02, TYPE_HEX, trvk_pkg0Offset0);
    trvk_pkg0Size = strtol(trvk_pkg0Offset0,NULL,16);
    trvk_pkg0FilledSize = 0x080FF0 - trvk_pkg0Size - SectionTOC[trvk_pkg0].Offset - 0x10;
    //printf("debug: trvk_pkg0Size:'0x%08X' trvk_pkg0FilledSize:'0x%08X' \n",trvk_pkg0Size,trvk_pkg0FilledSize);
    
    GetSection(FileToRead, SectionTOC[trvk_pkg1].Offset+0x0E, 0x02, TYPE_HEX, trvk_pkg1Offset0);
    trvk_pkg1Size = strtol(trvk_pkg1Offset0,NULL,16);
    trvk_pkg1FilledSize = 0x0A0FF0 - trvk_pkg1Size - SectionTOC[trvk_pkg1].Offset - 0x10;
    //printf("debug: trvk_pkg1Size:'0x%08X' trvk_pkg1FilledSize:'0x%08X' \n",trvk_pkg1Size,trvk_pkg1FilledSize);
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
    //printf("debug: ros0Size:'0x%08X' ros0FilledSize:'0x%08X' \n",ros0Size,ros0FilledSize);

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
    //printf("debug: ros1Size:'0x%08X' ros1FilledSize:'0x%08X' \n",ros1Size,ros1FilledSize);

    struct Sections SectionFilled[] = {
        {"flashformat"     , 0x000210                                         , 0x01F0             , TYPE_HEX, 1, "FF"},
        {"asecure_loader"  , SectionTOC[asecure_loader].Offset+0x40+metldrSize, metldrFilledSize   , TYPE_HEX, 1, "00"},
        {"eEID"            , 0x030DD0                                         , 0xE230             , TYPE_HEX, 1, "FF"},
        {"cISD"            , 0x03F270                                         , 0x0590             , TYPE_HEX, 1, "FF"},
        {"cCSD"            , 0x03F850                                         , 0x07B0             , TYPE_HEX, 1, "FF"},
        {"trvk_prg0"       , SectionTOC[trvk_prg0].Offset+0x10+trvk_prg0Size  , trvk_prg0FilledSize, TYPE_HEX, 1, "xx"}, // 00 
        {"trvk_prg0"       , 0x040FF0                                         , 0x01F010           , TYPE_HEX, 1, "xx"}, // FF 
        {"trvk_prg1"       , SectionTOC[trvk_prg1].Offset+0x10+trvk_prg1Size  , trvk_prg1FilledSize, TYPE_HEX, 1, "xx"}, // 00
        {"trvk_prg1"       , 0x060FF0                                         , 0x01F010           , TYPE_HEX, 1, "xx"}, // FF
        {"trvk_pkg0"       , SectionTOC[trvk_pkg0].Offset+0x10+trvk_pkg0Size  , trvk_pkg0FilledSize, TYPE_HEX, 1, "xx"}, // 00
        {"trvk_pkg0"       , 0x080FF0                                         , 0x01F010           , TYPE_HEX, 1, "xx"}, // FF
        {"trvk_pkg1"       , SectionTOC[trvk_pkg1].Offset+0x10+trvk_pkg1Size  , trvk_pkg1FilledSize, TYPE_HEX, 1, "xx"}, // 00
        {"trvk_pkg1"       , 0x0A0FF0                                         , 0x01F010           , TYPE_HEX, 1, "xx"}, // FF
        {"ros0"            , SectionTOC[ros0].Offset+ ros0Size                , ros0FilledSize     , TYPE_HEX, 1, "xx"}, // 00 need to investigate
        //{"ros0"            , SectionTOC[ros0].Offset+ ros0Size+ ros0FilledSize, 0x10               , TYPE_HEX, 1, "xx"}, // FF need to investigate
        {"ros1"            , SectionTOC[ros1].Offset+ ros1Size                , ros1FilledSize     , TYPE_HEX, 1, "xx"}, // 00 need to investigate
        //{"ros1"            , SectionTOC[ros1].Offset+ ros1Size+ ros1FilledSize, 0x10               , TYPE_HEX, 1, "xx"}, // FF need to investigate
//      {"cvtrm"           , 0xECxxxx                                         , 0x0xxxxx           , TYPE_HEX, 1, "00"}, // need to investigate
        {"CELL_EXTNOR_AREA", 0xF20040                                         , 0x01C0             , TYPE_HEX, 1, "00"},
        {"CELL_EXTNOR_AREA", 0xF20240                                         , 0x01FDC0           , TYPE_HEX, 1, "00"},
        {"CELL_EXTNOR_AREA", 0xF40030                                         , 0x01FFD0           , TYPE_HEX, 1, "00"},
        {"CELL_EXTNOR_AREA", 0xF60060                                         , 0x93A0             , TYPE_HEX, 1, "00"}, // need to calculate the correct start, size seems to be found at 0xF60000E on 2 bytes ?
        {"CELL_EXTNOR_AREA", 0xF69530                                         , 0x06D0             , TYPE_HEX, 1, "00"},
        {"CELL_EXTNOR_AREA", 0xF69C00                                         , 0x015400           , TYPE_HEX, 1, "FF"},
        {"CELL_EXTNOR_AREA", 0xF80030                                         , 0x01FFD0           , TYPE_HEX, 1, "00"},
        {"CELL_EXTNOR_AREA", 0xFA0060                                         , 0x93A0             , TYPE_HEX, 1, "00"}, // need to calculate the correct start, size seems to be found at 0xFA0000E on 2 bytes ?
        {"CELL_EXTNOR_AREA", 0xFA9530                                         , 0x06D0             , TYPE_HEX, 1, "00"},
        {"CELL_EXTNOR_AREA", 0xFA9C00                                         , 0x015400           , TYPE_HEX, 1, "FF"},
        {"bootldr"         , SectionTOC[bootldr].Offset+bootldrSize           , bootldrFilledSize  , TYPE_HEX, 1, "FF"},
        {NULL, 0, 0, 0, 0, NULL}
    };

    while (SectionFilled[Cursor].name!=NULL) {
        Status3 = EXIT_SUCCESS;
        if (strcmp(SectionFilled[Cursor].Pattern,"xx")==0) {
            for (Cursor2=0;Cursor2<SectionFilled[Cursor].Size;Cursor2++) {
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
                if (Status2) {
                    printf ("Error at '0x%08X\n",SectionFilled[Cursor].Offset+Cursor2);
                }
                Status3 |= Status2;
            }
            if (!Status3) {
                printf ("Succesfully checked '%s' From '0x%08X' size: '0x%08X' full of '00' xor 'FF'\n",SectionFilled[Cursor].name,SectionFilled[Cursor].Offset, SectionFilled[Cursor].Size);
            }
            else {
                printf ("Some error occured when checking '%s'\n",SectionFilled[Cursor].name);
            }
            
        }
        else {
            for (Cursor2=0;Cursor2<SectionFilled[Cursor].Size;Cursor2++) {
                //Status2 = EXIT_SUCCESS;
                Status2 = ReadSection(SectionFilled[Cursor].name
                    , FileToRead
                    , SectionFilled[Cursor].Offset+Cursor2
                    , 0x01
                    , SectionFilled[Cursor].DisplayType
                    , SectionFilled[Cursor].Check
                    , SectionFilled[Cursor].Pattern);
                if (Status2) {
                    printf ("Error at '0x%08X\n",SectionFilled[Cursor].Offset+Cursor2);
                }
                Status3 |= Status2;
            }
            if (!Status3) {
                printf ("Succesfully checked '%s' From '0x%08X' size: '0x%08X' full of '0x%s'\n",SectionFilled[Cursor].name,SectionFilled[Cursor].Offset, SectionFilled[Cursor].Size, SectionFilled[Cursor].Pattern);
            }
            else {
                printf ("Some error occured when checking '%s'\n",SectionFilled[Cursor].name);
            }
        }
        
        Cursor++;
        Status |= Status3;
        SizedCheck += SectionFilled[Cursor].Size;
    }
    //printf("debug: SectionTOC[trvk_prg0].Offset:'0x%08X' SectionTOC[trvk_prg0].Offset+0x10+trvk_prg0Size:'0x%08X' trvk_pkg0FilledSize:'0x%08X'\n",SectionTOC[trvk_prg0].Offset,SectionTOC[trvk_prg0].Offset+0x10+trvk_prg0Size,trvk_pkg0FilledSize);

    *PercentCheck = SizedCheck;

    free(Buffer);
    free(metldrOffset0);
    free(bootldrOffset0);
    free(trvk_prg0Offset0);
    free(trvk_prg1Offset0);
    free(trvk_pkg0Offset0);
    free(trvk_pkg1Offset0);
    //free(ros0Offset0);
    //free(ros1Offset0);

    return Status;
}

//
int main(int argc, char *argv[]) {
    uint8_t  Status = EXIT_SUCCESS;
    uint8_t  GlobalStatus = EXIT_SUCCESS;
    FILE     *BinaryFile;
    uint32_t FileLength;
    char     *Buffer = malloc(DATA_BUFFER_SIZE);
    uint8_t  Cursor;
    int      OptionType=0;
    struct   Options Option[NB_OPTIONS];
    uint32_t ExtractionSize;
    char     DisplaySection[DATA_BUFFER_SIZE];
    uint32_t *SizedCheck = malloc(sizeof(uint32_t)+1);
    uint32_t GlobalSizedCheck=0;
    uint8_t  GlobalReport[NBToReport]={0};
    
    struct Reporting ReportDetail[] = {
        {ReportMD5,            "MD5 Sum"              , "See report above or run again with option -M only"},
        {ReportExtraction,     "Section Extraction"   , "See report above or run again with option -E with start and size of section to try to extract"},
        {ReportStatistics,     "Statistics"           , "See report above or run again with option -P only"},
        {ReportGenericData,    "Generic Data Checking", "See report above or run again with option -G only"},
        {ReportPerConsoleData, "Per PS3 Data Checking", "See report above or run again with option -C only"},
        {ReportFilledArea,     "00/FF filled area"    , "See report above or run again with option -F only"},
        {0,NULL, NULL}
    };

    printf("******************************\n");
    printf("*       NOR Dump Tool        *\n");
    printf("******************************\n");
    printf("\nVersion 0.9.6\n");
    printf("\nOpen source project aimed to help to validate PS3 NOR dumps\n");
    printf("At the moment (January 2013) the code is probably able\n");
    printf("to give you a validation status of roughly 95%%!?\n");
    printf("It's anyway better to do additional checking by your own,\n");
    printf("unless the code of this tool is fully validated by experts!!!\n\n");

    if ((argc < 2)||(strcmp(argv[1], "--help")==0)) {
        printf("Usage: %s NorFile.bin (Options)\n", argv[0]);
        printf("Options:\n");
        printf("\t--help: Display this help.\n");
        printf("\t-P : Give percentage of bytes\n");
        printf("\t-G : Check PS3 Generic information\n");
        printf("\t-C : Check and display perconsole information\n");
        printf("\t-F : Check areas filled with '00' or 'FF'\n");
        printf("\t-S FolderName : Split some NOR section to folder 'FolderName'\n");
        printf("\t-M Start Size : Run MD5 sum on file from 'Start' for 'Size' long\n");
        printf("\t-E FileName Start Size : Extract specific NOR Section from 'Start' for 'Size' long\n");
        printf("\t-D Start Size H/A : Display a specific NOR Section from 'Start' for 'Size' long,\n\t\tuse H or A for HEX or ASCII\n");
        printf("\nBy default -P -G -C and -F will be applied if no option is given\n");
        printf("\nRepo: <https://github.com/anaria28/NOR-Dump-Tool>\n");
        return EXIT_FAILURE;
    }

    if (argc==2) {
        OptionType = OPTION_STATS + OPTION_CHECK_GENERIC + OPTION_CHECK_PERPS3 + OPTION_CHECK_FILLED;
    }

    for (Cursor=1;Cursor<argc;Cursor++) {
        if (strcmp(argv[Cursor], "-S")==0) {
            OptionType += OPTION_SPLIT;
            Option[0].Name = argv[Cursor+1];
        }
        if (strcmp(argv[Cursor], "-M")==0) {
            OptionType += OPTION_MD5;
            Option[1].Start = strtol(argv[Cursor+1],NULL,0);
            Option[1].Size = strtol(argv[Cursor+2],NULL,0);
        }
        if (strcmp(argv[Cursor], "-E")==0) {
            OptionType += OPTION_EXTRACT;
            Option[2].Name = argv[Cursor+1];
            Option[2].Start = strtol(argv[Cursor+2],NULL,0);
            Option[2].Size = strtol(argv[Cursor+3],NULL,0);
        }
        if (strcmp(argv[Cursor], "-P")==0) {
            OptionType += OPTION_STATS;
        }
        if (strcmp(argv[Cursor], "-G")==0) {
            OptionType += OPTION_CHECK_GENERIC;
        }
        if (strcmp(argv[Cursor], "-C")==0){
            OptionType += OPTION_CHECK_PERPS3;
        }
        if (strcmp(argv[Cursor], "-D")==0){
            OptionType += OPTION_DISPLAY_AREA;
            Option[6].Start = strtol(argv[Cursor+1],NULL,0);
            Option[6].Size  = strtol(argv[Cursor+2],NULL,0);
            if (argc!=Cursor+3){
                if (strcmp(argv[Cursor+3], "H")==0)
                    Option[6].Type = TYPE_HEX+DISPLAY_ALWAYS;
                else if (strcmp(argv[Cursor+3], "A")==0)
                    Option[6].Type = TYPE_ASCII+DISPLAY_ALWAYS;
                else
                    Option[6].Type = TYPE_HEX+DISPLAY_ALWAYS;
            }
            else
                Option[6].Type = TYPE_HEX+DISPLAY_ALWAYS;
        }
        if (strcmp(argv[Cursor], "-F")==0){
            OptionType += OPTION_CHECK_FILLED;
        }
    }

    BinaryFile = fopen(argv[1], "rb");
    if (!BinaryFile) {
        printf("Failed to open %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    fseek(BinaryFile, 0, SEEK_END);
    if ((FileLength=ftell(BinaryFile))!=NOR_FILE_SIZE) {
        printf("File size not correct for NOR, %d Bytes instead of %d\n", FileLength, NOR_FILE_SIZE);
        return EXIT_FAILURE;
    }

    if (((OptionType)&(1<<0))==OPTION_SPLIT) {
        printf("******************************\n");
        printf("*     Splitting NOR Dump     *\n");
        printf("******************************\n");

        Status = MKDIR(Option[0].Name,777);

        if (chdir(Option[0].Name)){
            printf("Failed to use folder %s\n", Option[0].Name);
            return EXIT_FAILURE;
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
    }
    GlobalStatus |= Status;

    if (((OptionType)&(1<<1))==OPTION_MD5) {
        printf("******************************\n");
        printf("*     MD5 Sum on Section     *\n");
        printf("******************************\n");
        MD5SumFileSection("Chosen section MD5 sum is: ", BinaryFile, Option[1].Start, Option[1].Size);
    }

    if ( ((OptionType)&(1<<2))==OPTION_EXTRACT ) {
        printf("******************************\n");
        printf("*    Extracting Section      *\n");
        printf("******************************\n");
        GlobalStatus |= ExtractSection(Option[2].Name, BinaryFile, Option[2].Start, Option[2].Size);
    }

    if (((OptionType)&(1<<3))==OPTION_STATS) {
        if ( Statistics (BinaryFile) ){
            GlobalReport[ReportStatistics] = 1;
            GlobalStatus |= 1;
            }
    }
    

    // Checking not done yet for a byte reserved dump it's then better to warn and exit for now.
    if (   (ReadSection("ByteReserved? ", BinaryFile, SectionTOC[FlashStart].Offset+0x14, 0x04, TYPE_HEX, 1, "0FACE0FF")==EXIT_FAILURE)
         &&(ReadSection("ByteReserved? ", BinaryFile, SectionTOC[FlashStart].Offset+0x14, 0x04, TYPE_HEX, 1, "AC0FFFE0")==EXIT_SUCCESS))
    {
        printf("\n\nNot treating byte reversed dump at the moment.\n");
        printf("Try again after reversing your file.\n");
        return EXIT_FAILURE;
    }

    if (((OptionType)&(1<<4))==OPTION_CHECK_GENERIC) {
        if((Status = CheckGenericData(BinaryFile, SizedCheck))) {
            printf("Some checking were not successful.\n");
            printf("You may need to check further your dump.\n");
            printf("But fortunately for the Generic section of the NOR it may be fixed.\n");
            GlobalReport[ReportGenericData] = 1;
        }
        else {
            printf("Seems good, but you'd eventually like to be carefull!\n");
        }
    }
    GlobalStatus |= Status;
    GlobalSizedCheck += *SizedCheck;
    if (((OptionType)&(1<<5))==OPTION_CHECK_PERPS3) {
        if((Status = CheckPerConsoleData(BinaryFile, SizedCheck))) {
            printf("Some checking were not successful.\n");
            printf("You may need to check further your dump.\n");
            printf("Be cautious, flashing this one may lead to a brick of your PS3.\n");
            GlobalReport[ReportPerConsoleData] = 1;
        }
        else {
            printf("Seems good, but you'd eventually like to be carefull!\n");
        }
    }
    GlobalStatus |= Status;
    GlobalSizedCheck += *SizedCheck;

    if (((OptionType)&(1<<6))==OPTION_DISPLAY_AREA) {
        sprintf(DisplaySection, "Start at '0x%08X' of size '0x%02X'", Option[6].Start, Option[6].Size);
        Status = ReadSection(DisplaySection, BinaryFile, Option[6].Start, Option[6].Size, Option[6].Type, 0, "");
    }

    if (((OptionType)&(1<<7))==OPTION_CHECK_FILLED) {
        if((Status = CheckFilledData(BinaryFile, SizedCheck))) {
            printf("Some checking were not successful.\n");
            printf("You may need to check further your dump.\n");
            printf("Be cautious there is something fishy in your dump.\n");
            GlobalReport[ReportFilledArea] = 1;
        }
        else {
            printf("Seems good, but you'd eventually like to be carefull!\n");
        }
    }
    GlobalStatus |= Status;
    GlobalSizedCheck += *SizedCheck;
    printf("\n\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    printf("\t! %02.2f%% of the file has been checked !\n", (double)GlobalSizedCheck*100/(double)NOR_FILE_SIZE);
    printf("\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");

    if (GlobalStatus){
        printf("\n");
        for (Cursor=1;Cursor<NBToReport;Cursor++) {
            if (GlobalReport[Cursor]){
                printf("\tError in %s\n",ReportDetail[Cursor].ReportName);
                printf("\t\t-%s\n",ReportDetail[Cursor].ReportMsg);
            }
        }
        printf("\n");
        printf("\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        printf("\t! YOU FAIL come back later !\n");
        printf("\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    }
    else{
        printf("\n");
        printf("\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        printf("\t! GOOD, same player, play again!? !\n");
        printf("\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    }
    free(SizedCheck);
    free(Buffer);
    fclose(BinaryFile);
    return GlobalStatus;
}
