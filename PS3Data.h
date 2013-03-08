
#define NOR_FILE_SIZE       0x1000000

#define NB_MAX_FILE_ROS     30

#define NB_REGION_FLASH     0x0B

#define MIN00               3083652
#define MAX00               4867070
#define MINFF               1748186
#define MAXFF               1758252
#define MAXOTHERS           83886
// Liste of structures used in NOR Dump Tool code and its includes

struct AddrLine
{
    uint32_t    Address;
    char       *LineName;
};

enum Line
{
    A0=0,
    A1,
    A2,
    A3,
    A4,
    A5,
    A6,
    A7,
    A8,
    A9,
    A10,
    A11,
    A12,
    A13,
    A14,
    A15,
    A16,
    A17,
    A18,
    A19,
    A20,
    A21,
    A22,
    A23,
    A24,
    A25,
    A26,
    A27,
    A28,
    A29,
    A30
};

static struct AddrLine AddressLine[] =
{
    {0x00000002, "A0"},
    {0x00000004, "A1"},
    {0x00000008, "A2"},
    {0x00000010, "A3"},
    {0x00000020, "A4"},
    {0x00000040, "A5"},
    {0x00000080, "A6"},
    {0x00000100, "A7"},
    {0x00000200, "A8"},
    {0x00000400, "A9"},
    {0x00000800, "A10"},
    {0x00001000, "A11"},
    {0x00002000, "A12"},
    {0x00004000, "A13"},
    {0x00008000, "A14"},
    {0x00010000, "A15"},
    {0x00020000, "A16"},    // used to check reptition for 0x14 & 0x00020014 & 0x00040014 & 0x00060014 & 0x00080014 ...
    {0x00040000, "A17"},    // used to check reptition for 0x14 & 0x00040014 & 0x00080014 & 0x000C0014
    {0x00080000, "A18"},    // used to check reptition for 0x14 & 0x00080014
    {0x00100000, "A19"},
    {0x00200000, "A20"},
    {0x00400000, "A21"},
    {0x00800000, "A22"},
    {0x01000000, "A23"},
    {0x02000000, "A24"},
    {0x04000000, "A25"},
    {0x08000000, "A26"},    //
    {0x10000000, "A27"},
    {0x20000000, "A28"},
    {0x40000000, "A29"},
    {0x80000000, "A30"},
    {0, NULL}
};

struct DatabaseMD5
{
    char       *Type;
    char       *Version;
    char       *MD5;
};

struct Sections
{
    char       *name;
    uint32_t   Offset;
    uint32_t   Size;
    int        DisplayType;
    int        Check;
    char       *Pattern;
};

struct IndividualSystemData
{
    char     *IDPSTargetID;     // 0x02F077 (NOR) 0x80877 (NAND)
    char     *SKU;              //
    char     *metldrOffset0;    // 0x081E (NOR) 0x4081E (NAND)
    char     *metldrOffset1;    // 0x0842 (NOR) 0x40842 (NAND)
    uint32_t  bootldrSize;
    char     *bootldrOffset0;   // 0xFC0002 (NOR) 0x02 (NAND)
    char     *bootldrOffset1;   // 0xFC0012 (NOR) 0x12 (NAND)
    char     *MinFW;
//    char *revision;
};

enum TOCnames
{
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
    CRL1,
    DRL1,
    CRL2,
    DRL2,
    bootldr,
    FlashStart,
    FlashFormat,
    FlashRegion,
    TotalSections
};

// http://www.ps3devwiki.com/wiki/Flash
static struct Sections SectionTOC[] =
{
    { "asecure_loader"  , 0x000800, 0x02E800, 0, 0, NULL }, // per console
    { "eEID"            , 0x02F000, 0x010000, 0, 0, NULL }, // per console
    { "cISD"            , 0x03F000, 0x0800  , 0, 0, NULL }, // per console
    { "cCSD"            , 0x03F800, 0x0800  , 0, 0, NULL }, // per console
    { "trvk_prg0"       , 0x040000, 0x020000, 0, 0, NULL }, // per firmware
    { "trvk_prg1"       , 0x060000, 0x020000, 0, 0, NULL }, // per firmware
    { "trvk_pkg0"       , 0x080000, 0x020000, 0, 0, NULL }, // per firmware
    { "trvk_pkg1"       , 0x0A0000, 0x020000, 0, 0, NULL }, // per firmware
    { "ros0"            , 0x0C0000, 0x700000, 0, 0, NULL }, // per firmware
    { "ros1"            , 0x7C0000, 0x700000, 0, 0, NULL }, // per firmware
    { "cvtrm"           , 0xEC0000, 0x040000, 0, 0, NULL }, // per console
    { "CELL_EXTNOR_AREA", 0xF20000, 0x020000, 0, 0, NULL }, // generic
    { "CRL1"            , 0xF40000, 0x020000, 0, 0, NULL }, // generic
    { "DRL1"            , 0xF60000, 0x020000, 0, 0, NULL }, // generic
    { "CRL2"            , 0xF80000, 0x020000, 0, 0, NULL }, // generic
    { "DRL2"            , 0xFA0000, 0x020000, 0, 0, NULL }, // generic
    { "bootldr"         , 0xFC0000, 0x040000, 0, 0, NULL }, // per console
    { "FlashStart"      , 0x000000, 0x0200  , 0, 0, NULL }, // generic
    { "FlashFormat"     , 0x000200, 0x0200  , 0, 0, NULL }, // generic
    { "FlashRegion"     , 0x000400, 0x0400  , 0, 0, NULL }, // generic
    { NULL, 0, 0, 0, 0, NULL }
};


//http://www.ps3devwiki.com/wiki/Talk:Flash:Individual_System_Data_-_cISD
//http://www.ps3devwiki.com/wiki/Validating_flash_dumps
static struct IndividualSystemData CheckPerSKU[] =
{
    { "01", "DEH-Z1010",                                       "1420", "113E", 0x2D020, "2CFE", "2CFE", "<= 0.80.004" }, // 0
    { "01", "DECR-1000",                                       "EC40", "0EC0", 0x2A840, "2A7F", "2A7F", "<= 0.85.009" },
    { "01", "DEH-H1001-D?",                                    "EC40", "0EC0", 0x2A830, "2A7F", "2A7F", "<= 0.85.009" },
    { "01", "DEH-H1000A-E (COK-001) DEX",                      "EC70", "0EC3", 0x2A1E0, "2A1A", "2A1A", "< 095.001" },
    { "01", "CECHAxx (COK-001)",                               "EE10", "0EDD", 0x2A430, "2A3F", "2A3F", "1.00" },
    { "01", "CECHAxx (COK-001) factory FW 1.00",               "EDA0", "0ED6", 0x2A2E0, "2A2A", "2A2A", "1.00" },
    { "01", "CECHAxx (COK-001)",                               "EDE0", "0EDA", 0x2A3B0, "2A37", "2A37", "1.00" },
    { "01", "DECHAxx (COK-001) DEX",                           "EDA0", "0ED6", 0x2A2E0, "2A2A", "2A2A", "1.00" },
    { "02", "CECHBxx (COK-001)",                               "EDA0", "0ED6", 0x2A2E0, "2A2A", "2A2A", "1.00" },
    { "03", "CECHCxx (COK-002)",                               "EDA0", "0ED6", 0x2A2E0, "2A2A", "2A2A", "1.00" },
    { "03", "CECHCxx (COK-002) factory FW 1.00",               "EBF0", "0EBB", 0x30480, "3044", "3044", "1.00" },
    { "03", "CECHCxx (COK-002)",                               "EDE0", "0EDA", 0x2A3B0, "2A37", "2A37", "1.00" },
    { "03", "CECHExx (COK-002)",                               "EA60", "0EA2", 0x2EE70, "2EE3", "2EE3", "1.97" },
    { "04", "Namco System 357 (COK-002) ARC",                  "E7B0", "0E77", 0x2E900, "2E8C", "2E8C", "1.90?" },
    { "04", "CECHExx (COK-002)",                               "EE10", "0EDD", 0x2A430, "2A3F", "2A3F", "1.00" },
    { "05", "CECHGxx (SEM-001)",                               "E7B0", "0E77", 0x2E900, "2E8C", "2E8C", "1.90" },
    { "05", "CECHGxx (SEM-001)",                               "E7B0", "0E77", 0x2F200, "2F1C", "2F1C", "2.30" },
    { "05", "CECHGxx (SEM-001)",                               "E8C0", "0E88", 0x2EF80, "2EF4", "2EF4", "2.30" },
    { "06", "CECHHxx (DIA-001)",                               "E7B0", "0E77", 0x2F200, "2F1C", "2F1C", "2.30" },
    { "06", "CECHHxx (DIA-001)",                               "E8C0", "0E88", 0x2EF80, "2EF4", "2EF4", "2.30" },
    { "06", "CECHHxx (DIA-001)",                               "E8E0", "0E8A", 0x2EF80, "2EF4", "2EF4", "1.97" }, // 20
    { "06", "CECHHxx (DIA-001)",                               "EA60", "0EA2", 0x2EE70, "2EE3", "2EE3", "1.97" },
    { "06", "CECHMxx (DIA-001)",                               "EA60", "0EA2", 0x2EE70, "2EE3", "2EE3", "1.97" },
    { "07", "CECHJxx (DIA-002) factory FW 2.30 - datecode 8B", "E8E0", "0E8A", 0x2EF80, "2EF4", "2EF4", "2.30" },
    { "07", "CECHJxx (DIA-002)",                               "EA60", "0EA2", 0x2EE70, "2EE3", "2EE3", "2.30" },
    { "07", "CECHKxx (DIA-002) datecode 8C",                   "EA60", "0EA2", 0x2EE70, "2EE3", "2EE3", "2.30" },
    { "07", "DECHJxx (DIA-002) DEX",                           "E8D0", "0E89", 0x2EAF0, "2EAB", "2EAB", "2.16" },
    { "08", "Namco System 357 (VER-001) ARC",                  "E8D0", "0E89", 0x2EAF0, "2EAB", "2EAB", "2.45?" },
    { "08", "CECHLxx/CECHPxx (VER-001) ",                      "E8D0", "0E89", 0x2EAF0, "2EAB", "2EAB", "2.45" },
    { "08", "CECHLxx (VER-001)",                               "E8D0", "0E89", 0x2EB70, "2EB3", "2EB3", "2.45" },
    { "08", "CECHLxx (VER-001) factory FW 2.30",               "E890", "0E85", 0x2F170, "2F13", "2F13", "2.30" }, // 30
    { "09", "CECH-20xx (DYN-001) factory FW 2.76",             "E890", "0E85", 0x2F170, "2F13", "2F13", "2.70" },
    { "09", "DECR-1400 (DEB-001) DECR factory FW 2.60",        "E890", "0E85", 0x2F170, "2F13", "2F13", "2.60" },
    { "09", "CECH-20xx (DYN-001)",                             "E920", "0E8E", 0x2F3F0, "2F3B", "2F3B", "2.70" },
    { "0A", "CECH-21xx (SUR-001)",                             "E920", "0E8E", 0x2F4F0, "2F4B", "2F4B", "3.20" },
    { "0B", "CECH-25xx (JTP-001) factory FW 3.40 datecode 0C", "E920", "0E8E", 0x2F4F0, "2F4B", "2F4B", "3.40" }, // 35
    { "0B", "CECH-25xx (JSD-001) factory FW 3.41 datecode 0C", "E920", "0E8E", 0x2F4F0, "2F4B", "2F4B", "3.40" }, // 36
    { "0B", "CECH-25xx (JSD-001) factory FW 3.56 datecode 0D", "E960", "0E92", 0x2F570, "2F53", "2F53", "3.50" }, // 37
    { "0B", "CECH-25xx (JTP-001) factory FW 3.56 datecode 1A", "E960", "0E92", 0x2F570, "2F53", "2F53", "3.50" }, // 38
    { "0B", "CECH-25xx (JTP-001) factory FW 3.56 datecode 1A", "E960", "0E92", 0x2F5F0, "2F5B", "2F5B", "3.56" }, // 39
    { "0B", "CECH-25xx (JSD-001) factory FW 3.56 datecode 1B", "E960", "0E92", 0x2F5F0, "2F5B", "2F5B", "3.56" }, // 40
    { "0B", "CECH-25xx (JTP-001) factory FW 3.56 datecode 1B", "E960", "0E92", 0x2F5F0, "2F5B", "2F5B", "3.56" },
    { "0B", "CECH-25xx (JSD-001) factory FW 3.60 datecode 1B", "F920", "0F8E", 0x2FFF0, "2FFB", "2FFB", "3.60" },
    { "0B", "CECH-25xx (JTP-001) factory FW 3.60",             "F920", "0F8E", 0x2FFF0, "2FFB", "2FFB", "3.60" },
    { "0C", "CECH-30xx (KTE-001) factory FW 3.65",             "F920", "0F8E", 0x2FFF0, "2FFB", "2FFB", "3.60" },
    { "0D", "CECH-40xx (MSX-001 or MPX-001)",                  "F9B0", "0F97", 0x301F0, "301B", "301B", "4.20" }, // 45
    { NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL}
};


// http://www.ps3devwiki.com/wiki/Talk:Flash:asecure_loader

// static struct IndividualSystemData CheckPerSKU[] = {
// { "01", "DEH-Z1010",                                       "1420", "113E", 0x2D020, "2CFE", "2CFE", "<= 0.80.004", "" }, // 0
// { "01", "DECR-1000",                                       "EC40", "0EC0", 0x2A840, "2A7F", "2A7F", "<= 0.85.009", "664566FA7788F8432FB7AA62" },
// { "01", "DEH-H1001-D?",                                    "EC40", "0EC0", 0x2A830, "2A7F", "2A7F", "<= 0.85.009", "664566FA7788F8432FB7AA62" },
// { "01", "DEH-H1000A-E (COK-001) DEX",                      "EC70", "0EC3", 0x2A1E0, "2A1A", "2A1A", "< 095.001"  , "8CC6E54B1D54DB912223390E" },
// { "01", "CECHAxx (COK-001)",                               "EE10", "0EDD", 0x2A430, "2A3F", "2A3F", "1"          , "" },
// { "01", "CECHAxx (COK-001) factory FW 1.00",               "EDA0", "0ED6", 0x2A2E0, "2A2A", "2A2A", "1"          , "48F43FDE3EEE37119C673663" }, // 5
// { "01", "CECHAxx (COK-001)",                               "EDE0", "0EDA", 0x2A3B0, "2A37", "2A37", "1"          , "81CF2EF41A336897E0493CB8" },
// { "01", "DECHAxx (COK-001) DEX",                           "EDA0", "0ED6", 0x2A2E0, "2A2A", "2A2A", "1"          , "48F43FDE3EEE37119C673663" },
// { "02", "CECHBxx (COK-001)",                               "EDA0", "0ED6", 0x2A2E0, "2A2A", "2A2A", "1"          , "48F43FDE3EEE37119C673663" },
// { "03", "CECHCxx (COK-002)",                               "EDA0", "0ED6", 0x2A2E0, "2A2A", "2A2A", "1"          , "48F43FDE3EEE37119C673663" },
// { "03", "CECHCxx (COK-002) factory FW 1.00",               "EBF0", "0EBB", 0x30480, "3044", "3044", "1"          , "94C6A30BBF2F50752E8DC052" }, // 10
// { "03", "CECHCxx (COK-002)",                               "EDE0", "0EDA", 0x2A3B0, "2A37", "2A37", "1"          , "81CF2EF41A336897E0493CB8" },
// { "03", "CECHExx (COK-002)",                               "EA60", "0EA2", 0x2EE70, "2EE3", "2EE3", "0.00"       , "" },
// { "04", "Namco System 357 (COK-002) ARC",                  "E7B0", "0E77", 0x2E900, "2E8C", "2E8C", "1.90?"      , "1362F2C2E6835D6FC144F246" },
// { "04", "CECHExx (COK-002)",                               "EE10", "0EDD", 0x2A430, "2A3F", "2A3F", "1"          , "2F6C622ECA7FAE0D2F76B5D4" },
// { "05", "CECHGxx (SEM-001)",                               "E7B0", "0E77", 0x2E900, "2E8C", "2E8C", "1.9"        , "" }, // 15
// { "05", "CECHGxx (SEM-001)",                               "E7B0", "0E77", 0x2F200, "2F1C", "2F1C", "2.3"        , "" },
// { "05", "CECHGxx (SEM-001)",                               "E8C0", "0E88", 0x2EF80, "2EF4", "2EF4", "2.3"        , "" },
// { "06", "CECHHxx (DIA-001)",                               "E7B0", "0E77", 0x2F200, "2F1C", "2F1C", "2.3"        , "" },
// { "06", "CECHHxx (DIA-001)",                               "E8C0", "0E88", 0x2EF80, "2EF4", "2EF4", "2.3"        , "7822C41EB9F00FA4830A0B69" }, // Found in the wiki
// { "06", "CECHHxx (DIA-001)",                               "E8E0", "0E8A", 0x2EF80, "2EF4", "2EF4", "1.97"       , "5E1F9CED758B6B94442BF031" }, // Found in the wiki
// { "06", "CECHHxx (DIA-001)",                               "EA60", "0EA2", 0x2EE70, "2EE3", "2EE3", "1.97"       , "" },
// { "06", "CECHMxx (DIA-001)",                               "EA60", "0EA2", 0x2EE70, "2EE3", "2EE3", "1.97"       , "" },
// { "07", "CECHJxx (DIA-002) factory FW 2.30 - datecode 8B", "E8E0", "0E8A", 0x2EF80, "2EF4", "2EF4", "2.3"        , "" },
// { "07", "CECHJxx (DIA-002)",                               "EA60", "0EA2", 0x2EE70, "2EE3", "2EE3", "2.3"        , "53E7EA237889AE20322A9708" },
// { "07", "CECHKxx (DIA-002) datecode 8C",                   "EA60", "0EA2", 0x2EE70, "2EE3", "2EE3", "2.3"        , "53E7EA237889AE20322A9708" }, // 25
// { "07", "DECHJxx (DIA-002) DEX",                           "E8D0", "0E89", 0x2EAF0, "2EAB", "2EAB", "2.16"       , "43B6EF4AE20F7400C8809E53" },
// { "08", "Namco System 357 (VER-001) ARC",                  "E8D0", "0E89", 0x2EAF0, "2EAB", "2EAB", "2.45?"      , "43B6EF4AE20F7400C8809E53" }, // 27
// { "08", "CECHLxx/CECHPxx (VER-001) ",                      "E8D0", "0E89", 0x2EAF0, "2EAB", "2EAB", "2.45"       , "43B6EF4AE20F7400C8809E53" }, // 28
// { "08", "CECHLxx (VER-001)",                               "E8D0", "0E89", 0x2EB70, "2EB3", "2EB3", "2.45"       , "43B6EF4AE20F7400C8809E53" }, // Found in the wiki
// { "08", "CECHLxx (VER-001) factory FW 2.30",               "E890", "0E85", 0x2F170, "2F13", "2F13", "2.3"        , "" }, // 30
// { "09", "CECH-20xx (DYN-001) factory FW 2.76",             "E890", "0E85", 0x2F170, "2F13", "2F13", "2.7"        , "BC78B8F02879A81184A0DA74" }, // 31
// { "09", "DECR-1400 (DEB-001) DECR factory FW 2.60",        "E890", "0E85", 0x2F170, "2F13", "2F13", "2.6"        , "BC78B8F02879A81184A0DA74" }, // 32
// { "09", "CECH-20xx (DYN-001)",                             "E920", "0E8E", 0x2F3F0, "2F3B", "2F3B", "2.7"        , "" },
// { "0A", "CECH-21xx (SUR-001)",                             "E920", "0E8E", 0x2F4F0, "2F4B", "2F4B", "3.2"        , "" },
// { "0B", "CECH-25xx (JTP-001) factory FW 3.40 datecode 0C", "E920", "0E8E", 0x2F4F0, "2F4B", "2F4B", "3.4"        , "99873BC715F280809C302225" }, // 35
// { "0B", "CECH-25xx (JSD-001) factory FW 3.41 datecode 0C", "E920", "0E8E", 0x2F4F0, "2F4B", "2F4B", "3.4"        , "99873BC715F280809C302225" }, // 36
// { "0B", "CECH-25xx (JSD-001) factory FW 3.56 datecode 0D", "E960", "0E92", 0x2F570, "2F53", "2F53", "3.5"        , "C3266E4BBB282E76B7677095" },
// { "0B", "CECH-25xx (JTP-001) factory FW 3.56 datecode 1A", "E960", "0E92", 0x2F570, "2F53", "2F53", "3.5"        , "C3266E4BBB282E76B7677095" },
// { "0B", "CECH-25xx (JTP-001) factory FW 3.56 datecode 1A", "E960", "0E92", 0x2F5F0, "2F5B", "2F5B", "3.56"       , "DBA53B0AB5181D971524615B" },
// { "0B", "CECH-25xx (JSD-001) factory FW 3.56 datecode 1B", "E960", "0E92", 0x2F5F0, "2F5B", "2F5B", "3.56"       , "DBA53B0AB5181D971524615B" }, // 40
// { "0B", "CECH-25xx (JSD-001) factory FW 3.60 datecode 1B", "F920", "0F8E", 0x2FFF0, "2FFB", "2FFB", "3.6"        , "" },
// { "0B", "CECH-25xx (JTP-001) factory FW 3.60",             "F920", "0F8E", 0x2FFF0, "2FFB", "2FFB", "3.6"        , "" },
// { "0C", "CECH-30xx (KTE-001) factory FW 3.65",             "F920", "0F8E", 0x2FFF0, "2FFB", "2FFB", "3.6"        , "" },
// { "0D", "CECH-40xx (MSX-001 or MPX-001)",                  "F9B0", "0F97", 0x301F0, "301B", "301B", "4.20"       , "A2834B1DFD969CC1769517C6" },
// { NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL}
// };

// http://www.ps3devwiki.com/wiki/Talk:Revokation
// below MD5 are calculated over the full space used by the revokation which includes tones of 00
// this typically corresponds to :
// MD5SumFileSection (FileToRead, SectionTOC[trvk_prg0].Offset+0x10, 0x0FE0, MD5result);
//
// calculating the MD5 on the section which is only containing pure data will give the same MD5 as the file found in a PUP
// which gives below code.
// GetSection(FileToRead, SectionTOC[trvk_prg0].Offset+0x0E, 0x02, TYPE_HEX, Buffer);
// trvk_prg0Size = strtol(Buffer,NULL,16);
// MD5SumFileSection (FileToRead, SectionTOC[trvk_prg0].Offset+0x10, trvk_prg0Size, MD5result);
// printMD5(MD5result);
//
// for example in a 3.55 Flash, "78629D24BD721488F3A1E846938F87DF" is the MD5 for trvk_prg0
// which is the exact same sum for the file in PUP:
//$ md5sum.exe 355/RL_FOR_PROGRAM.img
// 78629d24bd721488f3a1e846938f87df *355/RL_FOR_PROGRAM.img
//

static struct DatabaseMD5 trvk_prg_MD5[] =
{
    {"trvk_prg", "4.31"            , "7B84CFFB3DB4DB6C4F2ED264C5C413B0"},//0
    {"trvk_prg", "4.3"             , "38F41739F715A890598F3523FB56130C"},
    {"trvk_prg", "4.25_DEX"        , "7543C580101650016F52D921BB3D9C4E"},
    {"trvk_prg", "4.25"            , "7251547BB7C1F60F211FF991BF88083F"},
    {"trvk_prg", "4.21"            , "D27D88B0FA283458896439924C1364D1"},
    {"trvk_prg", "4.2"             , "06B819050E072F00E1CFBADA14D11042"},
    {"trvk_prg", "4.10/4.11"       , "1D364CE8487B2398A9E895C5C87748D9"},
    {"trvk_prg", "4"               , "A30722F12FA0872D87A156F85424013E"},
    {"trvk_prg", "3.73"            , "7342AFF50A0CE981DFFB07ABA742CC38"},
    {"trvk_prg", "3.72"            , "D2BE1629D2EB07F540A6735824B73537"},
    {"trvk_prg", "3.7"             , "59FBBD39CC17406E34F19C09F3DD9D64"},
    {"trvk_prg", "3.66/3.66_DEX"   , "AEEEF0B234E004DA7B9F10B80D51C137"},
    {"trvk_prg", "3.65"            , "E6C2B57E1BC810A9473448971775AF78"},
    {"trvk_prg", "3.61"            , "969702263EF47B8CAA3745FE1BF9B22D"},
    {"trvk_prg", "3.60/3.60_DEX"   , "38F60E2302C0ABEB88EF8058FBF45480"},
    {"trvk_prg", "3.56_2"          , "3369B79830062846EAD00BA82546C06C"},
    {"trvk_prg", "3.56_1"          , "B89DB85F620A44535B874744F5823CE1"},
    {"trvk_prg", "3.55/3.55_DEX"   , "9A3060D30A25DCE7686AA415A1857319"},
    {"trvk_prg", "3.50_DEX"        , "D7B99A10B7968C2E9710ABAE2CC765DD"},
    {"trvk_prg", "3.5"             , "C67C0E8750BE22D781C5168FE631145F"},
    {"trvk_prg", "3.42"            , "15C630F1EF0F70F968829783F34BBB4F"},
    {"trvk_prg", "3.41_2/3.41_DEX" , "B9FA9B2128677D0A0147BB1779A846AC"},
    {"trvk_prg", "3.4"             , "7B558127CCA04DC3031453AEAEA36066"},
    {"trvk_prg", "3.3"             , "E4B49673D8DFCFB8D1004D65F25E9A95"},
    {"trvk_prg", "3.21"            , "006CF0D4FA748A746B0FB2EF8B9F4462"},
    {"trvk_prg", "3.15/3.15_DEX"   , "B3D7874BF265BEA925531D4B6FD84575"},
    {"trvk_prg", "3.1"             , "D80CBA5A722EA10BD1EE452BBB9DE7C6"},
    {"trvk_prg", "3.01"            , "05029C4F31921A5B1E5199F586AC0099"},
    {"trvk_prg", "3"               , "EED1F52FEE408C5E9AAFA6797DC6C1EA"},
    {"trvk_prg", "2.8"             , "7C25D70ADE0FD709D182A9E07445E4EB"},
    {"trvk_prg", "2.76"            , "9E0C34B1C6DFCF85E86C254249F222FA"},
    {"trvk_prg", "2.7"             , "3534B73AD8417A35D5DC8B371B45A171"},
    {"trvk_prg", "2.6"             , "A34DB715070E75B3F7A76B48D7F3939D"},
    {"trvk_prg", "2.53"            , "EEBBAE430CE7A723C1769F77914FFC75"},
    {"trvk_prg", "2.52"            , "63E0721BD4C712738B8CFDEFE7A16D6D"},
    {"trvk_prg", "2.5"             , "AE6BD7BCAE934DF1D4A0364E8FFD8D2C"},
    {"trvk_prg", "2.43"            , "784C73FCA1FB0BBB9162585586701895"},
    {"trvk_prg", "2.42"            , "E73F305D7386AD65ECA1737DDB20C212"},
    {"trvk_prg", "2.41"            , "AF62192A127780A7F3FF74F497F2166B"},
    {"trvk_prg", "2.4"             , "592085BF608BA98CDCD97F83D0585D8B"},
    {"trvk_prg", "2.36"            , "30AEEDE2A064039CA6523CB81897ABB9"},
    {"trvk_prg", "2.35"            , "53FDFB27E75A071DA477E4E23BF5D95D"},
    {"trvk_prg", "2.3"             , "1DA4956E0716A221770700910B326DB6"},
    {"trvk_prg", "2.2"             , "6EC24DA67B34757552536F5A64031DE3"},
    {"trvk_prg", "2.17"            , "EBBEA9B7483468A5651E85508E6F9DDE"},
    {"trvk_prg", "2.1"             , "E5C8EF3D07917BC13C7E25BFB3181E22"},
    {"trvk_prg", "2.01"            , "0EF35CA6AE3B364CD43FBA5F7832B8D1"},
    {"trvk_prg", "2"               , "FC8C4389D17004220F2EB30909608066"},
    {"trvk_prg", "1.93"            , "0928C14E96D725C2FB161A42A3F44428"},
    {"trvk_prg", "1.92"            , "F06A8BBFBA08A4C648C8DA67DB4A4B36"},
    {"trvk_prg", "1.9"             , "9362B499D8FC74972E2C0CB401E85526"},
    {"trvk_prg", "1.82"            , "2C16DDCF3F130295DA202E6DDCC2A224"},
    {"trvk_prg", "1.81"            , "FAD825B3EEF1BDD213C74B58E8D695B8"},
    {"trvk_prg", "1.8"             , "C22F1C41342904C33A93B2BCC7A9514B"},
    {"trvk_prg", "1.7"             , "A039F8EBDC1993860EEA11B126377EAF"},
    {"trvk_prg", "1.6"             , "CAAC5DE89DAA2D79DB60F5972F2D7805"},
    {"trvk_prg", "1.54"            , "CB006FCF62FA064254E877F2BDEB463D"},
    {"trvk_prg", "1.51"            , "2643A3185DEFACC75F5C410BFDBFBA26"},
    {"trvk_prg", "1.5"             , "905694B5FFA1F0E49E4860E581B5653E"},
    {"trvk_prg", "1.32"            , "E86E439B43E079DBC6759638A9B84891"},
    {"trvk_prg", "1.31"            , "88D6850F99F3BA51FA6BB37FABC1A800"},
    {"trvk_prg", "1.3"             , "0DB00E61FA8134640800F2EFBCE6F8F9"},
    {"trvk_prg", "1.11"            , "410451085E6305BABE8D94FFF89F6C5C"},
    {"trvk_prg", "1.1"             , "FC0D846FD88982FB81564D7475590716"},
    {"trvk_prg", "1.02"            , "60A4B20FB5B6E09E700E799244C1BC46"},
    {NULL, NULL, NULL}
};

static struct DatabaseMD5 trvk_pkg_MD5[] =
{
    {"trvk_pkg", "4.25_DEX"                 , "6AB35C1F02B584AE84474D7ABECD6BDA"},
    {"trvk_pkg", "4.31"                     , "CCB14FE47C09CF4585127CFF2CE72693"},
    {"trvk_pkg", "4.30"                     , "CCB14FE47C09CF4585127CFF2CE72693"},
    {"trvk_pkg", "4.25"                     , "CCB14FE47C09CF4585127CFF2CE72693"},
    {"trvk_pkg", "4.21"                     , "CCB14FE47C09CF4585127CFF2CE72693"},
    {"trvk_pkg", "4.20"                     , "CCB14FE47C09CF4585127CFF2CE72693"},
    {"trvk_pkg", "4.11"                     , "B73491D0783489FEE31847261364ED41"},
    {"trvk_pkg", "4.10"                     , "B73491D0783489FEE31847261364ED41"},
    {"trvk_pkg", "4"                        , "BCBBD3B8F0D6F50AE45B06EC53E1DF3F"},
    {"trvk_pkg", "3.70/3.72/3.73"           , "3947F77FD2E2F997E1E03823C446FB60"},
    {"trvk_pkg", "3.66/3.66_DEX"            , "DE8E6C172782047479638C1EFEAF0F51"},
    {"trvk_pkg", "3.65"                     , "EA38E7F4598F5A20F3D5CBA0114AC727"},
    {"trvk_pkg", "3.61"                     , "16ADE352DAEDDA3FA63A202C767B4C7A"},
    {"trvk_pkg", "3.60/3.60_DEX"            , "FF273E1B10617FA053435672844A229D"},
    {"trvk_pkg", "3.56_2"                   , "A38264BAF9A6BDA0E5B1B2E32E2B6A28"},
    {"trvk_pkg", "3.56_1"                   , "E93A19A2DFE59DDA3C299EA3B9A7F045"},
    {"trvk_pkg", "3.55_DEX"                 , "3F807A034B6DCB21F53929B5D0570541"},
    {"trvk_pkg", "3.50_DEX"                 , "27B27ACD2075A04CF277C0335538157D"},
    {"trvk_pkg", "3.50/3.55"                , "9C050BB7146E394413804E9E1E9F7FA6"},
    {"trvk_pkg", "3.41_DEX"                 , "89B8674638DD06611C3D6946CC0231AE"},
    {"trvk_pkg", "3.40/3.41_2/3.42"         ," E080E353F2D9A1548E3014D2DC6B4BBD"},
    {"trvk_pkg", "3.3"                      , "BC3A89D6F7D66B64376C0DFF13D6B867"},
    {"trvk_pkg", "3.21"                     , "7BCF9B229FD7AF99F7AF955243129354"},
    {"trvk_pkg", "3.15/3.15_DEX"            , "9589EB7F93B5371E0CB60D454C67ADFA"},
    {"trvk_pkg", "3.1"                      , "EC0945F3AEA4A71A2E5E43C5A8ECD594"},
    {"trvk_pkg", "3.01"                     , "A7826026D5403024810EDC1E4DD77A52"},
    {"trvk_pkg", "3"                        , "95108E059B65E5C1CE6A4A8089089A60"},
    {"trvk_pkg", "2.8"                      , "32F5E69E8DE7B87DACC84A92E7025559"},
    {"trvk_pkg", "2.76"                     , "CDF88CA39FA271D25C18A2FBE5F9F7BE"},
    {"trvk_pkg", "2.7"                      , "22E2A99BA76E56F0957A7CF9FB145978"},
    {"trvk_pkg", "2.6"                      , "F36B3654D90C1578362A8A1510D0BBDD"},
    {"trvk_pkg", "2.53"                     , "DC0D0B66621C6DFB6704DBF28C58352C"},
    {"trvk_pkg", "2.52"                     , "26401229922C74D4C87D0DF003D235F1"},
    {"trvk_pkg", "2.5"                      , "22EFAB44D5CC3D7BA3AF05A4C283E1DA"},
    {"trvk_pkg", "2.43_LEAKED_JIG"          , "50AF53AF6D53F84D6D92EA6EFC5671DD"},
    {"trvk_pkg", "2.43"                     , "98BCA0307B2843A815176804947B68E0"},
    {"trvk_pkg", "2.42"                     , "93B7BE6B8302848FA27EBB8C3E01AE4B"},
    {"trvk_pkg", "2.41"                     , "505D3CFFFEA7E6085DB5A92C08BFD9BC"},
    {"trvk_pkg", "2.4"                      , "8DA31A5EDBE973EF0B054E34304F3BC4"},
    {"trvk_pkg", "2.36"                     , "FFD0D46F1B1675DA9A5A9E00AF5D71DD"},
    {"trvk_pkg", "2.35"                     , "B6E9AB2CCE06F244FE6BFED3C8244082"},
    {"trvk_pkg", "2.3"                      , "95CF8B4D7C88396AD71B2837909DD847"},
    {"trvk_pkg", "2.2"                      , "02DB8CA8361CEC854DFB339644A5D997"},
    {"trvk_pkg", "2.17"                     , "EC9DD3B077A4F42B42AF20A82E07A1EB"},
    {"trvk_pkg", "2.1"                      , "EBDB8D9CF82DC1F53ED1EAAC39851F6F"},
    {"trvk_pkg", "2.01"                     , "18B410877F6F962E92B7AECD91B1CF0C"},
    {"trvk_pkg", "2"                        , "4FCEFA3CFB8D731E90B53FC949151C91"},
    {"trvk_pkg", "1.93"                     , "36AD871B0BB839C02CB4BDDBE52FEFEA"},
    {"trvk_pkg", "1.92"                     , "B594EA4DB3B3A3D1FB02E0B2B6EE2201"},
    {"trvk_pkg", "1.9"                      , "A11A6F728B0086E9082BAD0506C58B94"},
    {"trvk_pkg", "1.82"                     , "653434FF27E82FAA04FFA038784A1E7B"},
    {"trvk_pkg", "1.81"                     , "C03376C49B7D028094C340E7369CE912"},
    {"trvk_pkg", "1.8"                      , "A17466375FC6B6E2E8D8B0F223012F85"},
    {"trvk_pkg", "1.7"                      , "3FAB9C9B2C13DAD1D634493F04C60609"},
    {"trvk_pkg", "1.6"                      , "29B657AB7327CD1F00B701AE6B7BC179"},
    {"trvk_pkg", "1.54"                     , "5D2516B29A9C2E56C3E1C5F2F5883FF0"},
    {"trvk_pkg", "1.51"                     , "39BB79DED88187372F06B2F5D393D777"},
    {"trvk_pkg", "1.5"                      , "847F9F54A392BCC3F059F2352F4E844C"},
    {"trvk_pkg", "1.32"                     , "D08A3FD2C5B8468C4980BCA014EAA47A"},
    {"trvk_pkg", "1.31"                     , "C01D8294B4F319DF0CD1CA6CC4480826"},
    {"trvk_pkg", "1.3"                      , "7111A00520ACE60D17BB23709F5EC4EC"},
    {"trvk_pkg", "1.11"                     , "6D49077177812D9D6FCD289FD1EDED90"},
    {"trvk_pkg", "1.1"                      , "EA03F7AC248C5B5228D8B40B13A27AE8"},
    {"trvk_pkg", "1.02"                     , "B7829DD4B09C25B6918BA78BDEACF07F"},
    {NULL, NULL, NULL}
};
// 43D940901E9655AD502C12D990977811 *RL_FOR_PROGRAM.341
// 78629D24BD721488F3A1E846938F87DF *RL_FOR_PROGRAM.355
// 78629D24BD721488F3A1E846938F87DF *RL_FOR_PROGRAM.355DBG
// 369E60A0E5FAC9A987A4098A48E636BB *RL_FOR_PROGRAM.356
// 333CC79D76D2717092196AEEE951DA12 *RL_FOR_PROGRAM.356-1
// 0287DBFFCB57382E032B363B5B582D3C *RL_FOR_PROGRAM.420
// 10F4271AACAFBB1AD7A9E51C5F798CC8 *RL_FOR_PROGRAM.421
// 848ADAB5B11FF0FE4AA25559B23B6840 *RL_FOR_PROGRAM.430
static struct DatabaseMD5 RL_FOR_PROGRAM_MD5[] =
{
    {"RL_FOR_PROGRAM", "4.25_DEX"                 , ""},
    {"RL_FOR_PROGRAM", "4.31"                     , ""},
    {"RL_FOR_PROGRAM", "4.30"                     , "848ADAB5B11FF0FE4AA25559B23B6840"},
    {"RL_FOR_PROGRAM", "4.25"                     , ""},
    {"RL_FOR_PROGRAM", "4.21"                     , "10F4271AACAFBB1AD7A9E51C5F798CC8"},
    {"RL_FOR_PROGRAM", "4.20"                     , "0287DBFFCB57382E032B363B5B582D3C"},
    {"RL_FOR_PROGRAM", "4.10/4.11"                , ""},
    {"RL_FOR_PROGRAM", "4"                        , ""},
    {"RL_FOR_PROGRAM", "3.70/3.72/3.73"           , ""},
    {"RL_FOR_PROGRAM", "3.66/3.66_DEX"            , ""},
    {"RL_FOR_PROGRAM", "3.65"                     , ""},
    {"RL_FOR_PROGRAM", "3.61"                     , ""},
    {"RL_FOR_PROGRAM", "3.60/3.60_DEX"            , ""},
    {"RL_FOR_PROGRAM", "3.56_2"                   , ""},
    {"RL_FOR_PROGRAM", "3.56_1"                   , "333CC79D76D2717092196AEEE951DA12"},
    {"RL_FOR_PROGRAM", "3.55_DEX"                 , "78629D24BD721488F3A1E846938F87DF"},
    {"RL_FOR_PROGRAM", "3.50_DEX"                 , ""},
    {"RL_FOR_PROGRAM", "3.50/3.55"                , "78629D24BD721488F3A1E846938F87DF"},
    {"RL_FOR_PROGRAM", "3.41_DEX"                 , ""},
    {"RL_FOR_PROGRAM", "3.40/3.41_2/3.42"         , "43D940901E9655AD502C12D990977811"},
    {"RL_FOR_PROGRAM", "3.3"                      , ""},
    {"RL_FOR_PROGRAM", "3.21"                     , ""},
    {"RL_FOR_PROGRAM", "3.15/3.15_DEX"            , ""},
    {"RL_FOR_PROGRAM", "3.1"                      , ""},
    {"RL_FOR_PROGRAM", "3.01"                     , ""},
    {"RL_FOR_PROGRAM", "3"                        , ""},
    {"RL_FOR_PROGRAM", "2.8"                      , ""},
    {"RL_FOR_PROGRAM", "2.76"                     , ""},
    {"RL_FOR_PROGRAM", "2.7"                      , ""},
    {"RL_FOR_PROGRAM", "2.6"                      , ""},
    {"RL_FOR_PROGRAM", "2.53"                     , ""},
    {"RL_FOR_PROGRAM", "2.52"                     , ""},
    {"RL_FOR_PROGRAM", "2.5"                      , ""},
    {"RL_FOR_PROGRAM", "2.43_LEAKED_JIG"          , ""},
    {"RL_FOR_PROGRAM", "2.43"                     , ""},
    {"RL_FOR_PROGRAM", "2.42"                     , ""},
    {"RL_FOR_PROGRAM", "2.41"                     , ""},
    {"RL_FOR_PROGRAM", "2.4"                      , ""},
    {"RL_FOR_PROGRAM", "2.36"                     , ""},
    {"RL_FOR_PROGRAM", "2.35"                     , ""},
    {"RL_FOR_PROGRAM", "2.3"                      , ""},
    {"RL_FOR_PROGRAM", "2.2"                      , ""},
    {"RL_FOR_PROGRAM", "2.17"                     , ""},
    {"RL_FOR_PROGRAM", "2.1"                      , ""},
    {"RL_FOR_PROGRAM", "2.01"                     , ""},
    {"RL_FOR_PROGRAM", "2"                        , ""},
    {"RL_FOR_PROGRAM", "1.93"                     , ""},
    {"RL_FOR_PROGRAM", "1.92"                     , ""},
    {"RL_FOR_PROGRAM", "1.9"                      , ""},
    {"RL_FOR_PROGRAM", "1.82"                     , ""},
    {"RL_FOR_PROGRAM", "1.81"                     , ""},
    {"RL_FOR_PROGRAM", "1.8"                      , ""},
    {"RL_FOR_PROGRAM", "1.7"                      , ""},
    {"RL_FOR_PROGRAM", "1.6"                      , ""},
    {"RL_FOR_PROGRAM", "1.54"                     , ""},
    {"RL_FOR_PROGRAM", "1.51"                     , ""},
    {"RL_FOR_PROGRAM", "1.5"                      , ""},
    {"RL_FOR_PROGRAM", "1.32"                     , ""},
    {"RL_FOR_PROGRAM", "1.31"                     , ""},
    {"RL_FOR_PROGRAM", "1.3"                      , ""},
    {"RL_FOR_PROGRAM", "1.11"                     , ""},
    {"RL_FOR_PROGRAM", "1.1"                      , ""},
    {"RL_FOR_PROGRAM", "1.02"                     , ""},
    {NULL, NULL, NULL}
};
// 30117B4E11FB67AD42F382E0A8049717 *RL_FOR_PACKAGE.341
// A3A29B8A29F7C057ADA56ECCB062325C *RL_FOR_PACKAGE.355
// 77F481E1BCF309FB9357FA1F1E7C7B39 *RL_FOR_PACKAGE.355DBG
// FBD76F774AC6B9ED96508B6C8973603E *RL_FOR_PACKAGE.356
// 526BE641D285D8697DA72EAB6EFDA9F5 *RL_FOR_PACKAGE.356-1
// AB428BEB148B89F7EEE75096EE36C7A3 *RL_FOR_PACKAGE.420
// AB428BEB148B89F7EEE75096EE36C7A3 *RL_FOR_PACKAGE.421
// AB428BEB148B89F7EEE75096EE36C7A3 *RL_FOR_PACKAGE.430
static struct DatabaseMD5 RL_FOR_PACKAGE_MD5[] =
{
    {"RL_FOR_PROGRAM", "4.25_DEX"                 , ""},
    {"RL_FOR_PROGRAM", "4.31"                     , ""},
    {"RL_FOR_PROGRAM", "4.30"                     , "AB428BEB148B89F7EEE75096EE36C7A3"},
    {"RL_FOR_PROGRAM", "4.25"                     , ""},
    {"RL_FOR_PROGRAM", "4.21"                     , "AB428BEB148B89F7EEE75096EE36C7A3"},
    {"RL_FOR_PROGRAM", "4.20"                     , "AB428BEB148B89F7EEE75096EE36C7A3"},
    {"RL_FOR_PROGRAM", "4.11"                     , ""},
    {"RL_FOR_PROGRAM", "4.10"                     , ""},
    {"RL_FOR_PROGRAM", "4"                        , ""},
    {"RL_FOR_PROGRAM", "3.70/3.72/3.73"           , ""},
    {"RL_FOR_PROGRAM", "3.66/3.66_DEX"            , ""},
    {"RL_FOR_PROGRAM", "3.65"                     , ""},
    {"RL_FOR_PROGRAM", "3.61"                     , ""},
    {"RL_FOR_PROGRAM", "3.60/3.60_DEX"            , ""},
    {"RL_FOR_PROGRAM", "3.56_2"                   , "FBD76F774AC6B9ED96508B6C8973603E"},
    {"RL_FOR_PROGRAM", "3.56_1"                   , "526BE641D285D8697DA72EAB6EFDA9F5"},
    {"RL_FOR_PROGRAM", "3.55_DEX"                 , "77F481E1BCF309FB9357FA1F1E7C7B39"},
    {"RL_FOR_PROGRAM", "3.50_DEX"                 , ""},
    {"RL_FOR_PROGRAM", "3.50/3.55"                , "78629D24BD721488F3A1E846938F87DF"},
    {"RL_FOR_PROGRAM", "3.41_DEX"                 , ""},
    {"RL_FOR_PROGRAM", "3.40/3.41_2/3.42"         , "43D940901E9655AD502C12D990977811"},
    {"RL_FOR_PROGRAM", "3.3"                      , ""},
    {"RL_FOR_PROGRAM", "3.21"                     , ""},
    {"RL_FOR_PROGRAM", "3.15/3.15_DEX"            , ""},
    {"RL_FOR_PROGRAM", "3.1"                      , ""},
    {"RL_FOR_PROGRAM", "3.01"                     , ""},
    {"RL_FOR_PROGRAM", "3"                        , ""},
    {"RL_FOR_PROGRAM", "2.8"                      , ""},
    {"RL_FOR_PROGRAM", "2.76"                     , ""},
    {"RL_FOR_PROGRAM", "2.7"                      , ""},
    {"RL_FOR_PROGRAM", "2.6"                      , ""},
    {"RL_FOR_PROGRAM", "2.53"                     , ""},
    {"RL_FOR_PROGRAM", "2.52"                     , ""},
    {"RL_FOR_PROGRAM", "2.5"                      , ""},
    {"RL_FOR_PROGRAM", "2.43_LEAKED_JIG"          , ""},
    {"RL_FOR_PROGRAM", "2.43"                     , ""},
    {"RL_FOR_PROGRAM", "2.42"                     , ""},
    {"RL_FOR_PROGRAM", "2.41"                     , ""},
    {"RL_FOR_PROGRAM", "2.4"                      , ""},
    {"RL_FOR_PROGRAM", "2.36"                     , ""},
    {"RL_FOR_PROGRAM", "2.35"                     , ""},
    {"RL_FOR_PROGRAM", "2.3"                      , ""},
    {"RL_FOR_PROGRAM", "2.2"                      , ""},
    {"RL_FOR_PROGRAM", "2.17"                     , ""},
    {"RL_FOR_PROGRAM", "2.1"                      , ""},
    {"RL_FOR_PROGRAM", "2.01"                     , ""},
    {"RL_FOR_PROGRAM", "2"                        , ""},
    {"RL_FOR_PROGRAM", "1.93"                     , ""},
    {"RL_FOR_PROGRAM", "1.92"                     , ""},
    {"RL_FOR_PROGRAM", "1.9"                      , ""},
    {"RL_FOR_PROGRAM", "1.82"                     , ""},
    {"RL_FOR_PROGRAM", "1.81"                     , ""},
    {"RL_FOR_PROGRAM", "1.8"                      , ""},
    {"RL_FOR_PROGRAM", "1.7"                      , ""},
    {"RL_FOR_PROGRAM", "1.6"                      , ""},
    {"RL_FOR_PROGRAM", "1.54"                     , ""},
    {"RL_FOR_PROGRAM", "1.51"                     , ""},
    {"RL_FOR_PROGRAM", "1.5"                      , ""},
    {"RL_FOR_PROGRAM", "1.32"                     , ""},
    {"RL_FOR_PROGRAM", "1.31"                     , ""},
    {"RL_FOR_PROGRAM", "1.3"                      , ""},
    {"RL_FOR_PROGRAM", "1.11"                     , ""},
    {"RL_FOR_PROGRAM", "1.1"                      , ""},
    {"RL_FOR_PROGRAM", "1.02"                     , ""},
    {NULL, NULL, NULL}
};

// see also
// http://www.ps3devwiki.com/wiki/Revokation
// http://www.ps3devwiki.com/wiki/Keys
// http://www.ps3devwiki.com/wiki/SELF_File_Format_and_Decryption
// http://www.ps3devwiki.com/wiki/Authentication_IDs

// not really useful I was just curious
// static struct DatabaseMD5 rosMD5[] = {
// {"ros0" , "4.11" , "479519FEE12E93D09B7430E62170B87F"},
// {"ros0" , "3.55" , "93E5B0B9FE5611AB1E7378DC38D1D266"},
// {"ros0" , "4.10" , "3DD58D297348872A963575B5C431AF7B"},
// {"ros1" , "4.00" , "E3439578CD59562CD325B12006C1068C"},
// {"ros0" , "4.25" , "34A52D68A4B73EBE7FCC0CCA14339A96"},
// {"ros1" , "4.20" , "2EC71148146DCECE412FE7BEBCA0DEFA"},
// {"ros0" , "3.66" , "F5D0C0A4E2BBBA2A0E05CDE2AB9C4DDE"},
// {"ros0" , "3.70" , "7D96F010ABA16517F1545D9059F158DB"},
// {"ros1" , "3.61" , "20B4513B13D067B5AF3E7209C6CC340F"},
// {NULL, NULL, NULL}
// };

static struct DatabaseMD5 rosFilesMD5[] =
{
    // FW 2.80 Files
    {"creserved_0" , "2.80" , "09A1D434DBD7197E7C3AF8A7C28CA38B"},
    {"sdk_version" , "2.80" , "9A5BAFBDA4C414E884A8B4F5F58E002C"},
    {"lv1ldr" , "2.80" , "CE5269534CB094D83C9CB6A9E199E4A3"},
    {"lv2ldr" , "2.80" , "592BB9EB64FC767EF0E65A3988771C3A"},
    {"isoldr" , "2.80" , "4A5253F71CA5A5C8CCFD8F990663BB74"},
    {"appldr" , "2.80" , "13BBEA44F0EB32DEDB7291DF2B441A75"},
    {"spu_pkg_rvk_verifier.self" , "2.80" , "D0F6BCA5055C0B839CD82D893B57F823"},
    {"spu_token_processor.self" , "2.80" , "18D2B38B032E4C6CD83AD207BC713384"},
    {"spu_utoken_processor.self" , "2.80" , "2E687F9D304AA82ED22BEB558876F719"},
    {"sc_iso.self" , "2.80" , "A16463EBCF1A78A7CFCCADFFA71A6C84"},
    {"aim_spu_module.self" , "2.80" , "168B6961664DDCBF9ADA4A383EE012B0"},
    {"spp_verifier.self" , "2.80" , "4F9020B1FA7A32CE5945817F435A993B"},
    {"mc_iso_spu_module.self" , "2.80" , "A41C00732C8F51389F080438806C69CD"},
    {"me_iso_spu_module.self" , "2.80" , "EBE216188215DDCC491B65C51AAD817F"},
    {"sv_iso_spu_module.self" , "2.80" , "C1D7E167B5F702C492091A104613F3CC"},
    {"sb_iso_spu_module.self" , "2.80" , "EE362071EA547D1D1486C4035514F3ED"},
    {"default.spp" , "2.80" , "B4809F998BA62B2A299A2769DBDB80F7"},
    {"lv1.self" , "2.80" , "828B5AA6D8C151A21F08AF59148F59D3"},
    {"lv0" , "2.80" , "DF7D71CFC9B04F6EE62DFBEDF30F0311"},
    {"lv2_kernel.self" , "2.80" , "C2BBC899ADBF70E4273568F81DF40086"},
    {"eurus_fw.bin" , "2.80" , "1DBE0FFFDE95D148ADF85009B2473A7D"},
    {"emer_init.self" , "2.80" , "15FC7A804B08B9B138FC164AE7750BD6"},
    // FW 3.41 Files
    {"creserved_0" , "3.41" , "09A1D434DBD7197E7C3AF8A7C28CA38B"},
    {"sdk_version" , "3.41" , "7A2595AECEDE95C9338C710CF8DBBA99"},
    {"lv1ldr" , "3.41" , "C7BF42F12A3EE32E694EB9FE46E1DB51"},
    {"lv2ldr" , "3.41" , "C8777688BF00F42E6C73DE336E10A25A"},
    {"isoldr" , "3.41" , "54490521B6965BD0E95D93928C1B4056"},
    {"appldr" , "3.41" , "CF08E9B3421E4B1AA665717C555ED670"},
    {"spu_pkg_rvk_verifier.self" , "3.41" , "964A28D0F0E6AA3423A4FF1DA4598C21"},
    {"spu_token_processor.self" , "3.41" , "7D71C9C119989446766442E8127BA0CB"},
    {"spu_utoken_processor.self" , "3.41" , "92913EAD973B8AA24BFF4F38FE66927E"},
    {"sc_iso.self" , "3.41" , "7E9938FF024C809DE3CC950B61E01F6B"},
    {"aim_spu_module.self" , "3.41" , "8C3DF66C7BCFCB291221884EE46CB351"},
    {"spp_verifier.self" , "3.41" , "A60518DDF46B904E7F8B4ADC96F60342"},
    {"mc_iso_spu_module.self" , "3.41" , "07DDFE013304965BF7EB63D9AC5BD0C2"},
    {"me_iso_spu_module.self" , "3.41" , "A237F20A0491149B1C0890B0FCE8E0CE"},
    {"sv_iso_spu_module.self" , "3.41" , "7D20C0D5F382EEB31E6B830EA1ED4B8F"},
    {"sb_iso_spu_module.self" , "3.41" , "5A219A19D772E26F41A86BCB8449093E"},
    {"default.spp" , "3.41" , "4E78EA91BE73C71012930C4144B50CC1"},
    {"lv1.self" , "3.41" , "200A67508DF9C6B2F47A7A93FF2160CA"},
    {"lv0" , "3.41" , "C0C71AE21AEC6A6116464B8A7DF4D534"},
    {"lv2_kernel.self" , "3.41" , "9DBFDC3B026622E83398554B783E1CEC"},
    {"eurus_fw.bin" , "3.41" , "B5F54D9A11D1EAE71F35B5907C6B9D3A"},
    {"emer_init.self" , "3.41" , "D5F6040AAB1B27E29461E847CFFDA08E"},
    {"hdd_copy.self" , "3.41" , "F1142B43BCD76C0EC9A0CBF1BE8BE407"},
    // FW 341 DEBUG
    //{"creserved_0" , "3.41" , "09a1d434dbd7197e7c3af8a7c28ca38b"},
    //{"sdk_version" , "3.41" , "7a2595aecede95c9338c710cf8dbba99"},
    //{"lv1ldr" , "3.41" , "c7bf42f12a3ee32e694eb9fe46e1db51"},
    //{"lv2ldr" , "3.41" , "c8777688bf00f42e6c73de336e10a25a"},
    //{"isoldr" , "3.41" , "54490521b6965bd0e95d93928c1b4056"},
    //{"appldr" , "3.41" , "cf08e9b3421e4b1aa665717c555ed670"},
    //{"spu_pkg_rvk_verifier.self" , "3.41" , "964a28d0f0e6aa3423a4ff1da4598c21"},
    //{"spu_token_processor.self" , "3.41" , "7d71c9c119989446766442e8127ba0cb"},
    //{"spu_utoken_processor.self" , "3.41" , "92913ead973b8aa24bff4f38fe66927e"},
    //{"sc_iso.self" , "3.41" , "7e9938ff024c809de3cc950b61e01f6b"},
    //{"aim_spu_module.self" , "3.41" , "8c3df66c7bcfcb291221884ee46cb351"},
    //{"spp_verifier.self" , "3.41" , "a60518ddf46b904e7f8b4adc96f60342"},
    //{"mc_iso_spu_module.self" , "3.41" , "07ddfe013304965bf7eb63d9ac5bd0c2"},
    //{"me_iso_spu_module.self" , "3.41" , "a237f20a0491149b1c0890b0fce8e0ce"},
    //{"sv_iso_spu_module.self" , "3.41" , "7d20c0d5f382eeb31e6b830ea1ed4b8f"},
    //{"sb_iso_spu_module.self" , "3.41" , "5a219a19d772e26f41a86bcb8449093e"},
    {"default.spp" , "3.41_DEX" , "1717C8A5B8BF564CC5B533493001B7B0"},
    {"lv1.self" , "3.41_DEX" , "08A08B36EB53BE628EFD612B11FF2568"},
    //{"lv0" , "3.41" , "c0c71ae21aec6a6116464b8a7df4d534"},
    {"lv2_kernel.self" , "3.41_DEX" , "BD4DE04E55EFED427F5289AF2AAD3A0E"},
    //{"eurus_fw.bin" , "3.41" , "b5f54d9a11d1eae71f35b5907c6b9d3a"},
    //{"emer_init.self" , "3.41" , "d5f6040aab1b27e29461e847cffda08e"},
    //{"hdd_copy.self" , "3.41" , "f1142b43bcd76c0ec9a0cbf1be8be407"},

    // FW 3.55 Files
    {"aim_spu_module.self" , "3.55" , "CA9BBC99C645173E1F98AA66C47A4500"},
    {"appldr" , "3.55" , "5C7436BFFC7E8D0A8E210BD0CA83CDF2"},
    {"creserved_0" , "3.55" , "09A1D434DBD7197E7C3AF8A7C28CA38B"},
    {"default.spp" , "3.55" , "B0AD88EE637311AE5196F1B11D43BE0A"},
    {"emer_init.self" , "3.55" , "9D670B662BE696C8460449B7EFDD803E"},
    {"eurus_fw.bin" , "3.55" , "B5F54D9A11D1EAE71F35B5907C6B9D3A"},
    {"hdd_copy.self" , "3.55" , "C1DC055EF0D6082580AC066E2B0A3C38"},
    {"isoldr" , "3.55" , "811329ECDB677181B9FC5CC3564D9047"},
    {"lv0" , "3.55" , "FF6753184D15F45508C5330A6144A4D9"},
    {"lv1.self" , "3.55" , "A58AA50C88EAC3C2084F2616DFE32660"},
    {"lv1ldr" , "3.55" , "E9AE2A62B4CC31750D4E56C7D5FFDD6F"},
    {"lv2_kernel.self" , "3.55" , "5FBB75E4090BB6D66674E64082D1DBC4"},
    {"lv2ldr" , "3.55" , "A597AA3D8101674856EEF83AC1D0EF28"},
    {"manu_info_spu_module.self" , "3.55" , "65A3EEE4C48716674CB1C29609B5F54D"},
    {"mc_iso_spu_module.self" , "3.55" , "5FFB33A6CECB99081E54A0E36E3C61AF"},
    {"me_iso_spu_module.self" , "3.55" , "3B15C14770D654FEF9987E2517616D89"},
    {"sb_iso_spu_module.self" , "3.55" , "B39E13FBD6B07F65616A0355EF5CB262"},
    {"sc_iso.self" , "3.55" , "D7EDCA0ED3749F11EE34F0F532CF5AA7"},
    {"sdk_version" , "3.55" , "3DA12E2CB472EB8193309B663D7C913A"},
    {"spp_verifier.self" , "3.55" , "90D1C8A45F6FEE52219E1B14FF8C9765"},
    {"spu_pkg_rvk_verifier.self" , "3.55" , "B76B7244B19032A9518787D9EC827F3C"},
    {"spu_token_processor.self" , "3.55" , "22ABABCFC027F892AD2CF4E1C9FD925C"},
    {"spu_utoken_processor.self" , "3.55" , "0E5A2E8A68FE09481D728C227DC5A165"},
    {"sv_iso_spu_module.self" , "3.55" , "368F2D290C00F3CB3C5A5C8CFE584534"},
    // FW 3.56 Files
    {"creserved_0" , "3.56" , "09a1d434dbd7197e7c3af8a7c28ca38b"},
    {"sdk_version" , "3.56" , "4ad31c47e7a2348c75a24b15135f9bf7"},
    {"lv1ldr" , "3.56" , "df983936617e156c7b25dba6d55c6f78"},
    {"lv2ldr" , "3.56" , "9819c9e6ee9c7f81ba291e8d15e3acf2"},
    {"isoldr" , "3.56" , "f83e05f3f0109e3cb11abedb952b5f2e"},
    {"appldr" , "3.56" , "8543bdca2ccf99a60da717ebe9f768c4"},
    {"spu_pkg_rvk_verifier.self" , "3.56" , "8341337b8d4167c4f93720a08822ed9f"},
    {"spu_token_processor.self" , "3.56" , "a16a4d50d2f92c4d7ae43b174dc47706"},
    {"spu_utoken_processor.self" , "3.56" , "1e9c84755ec25513a790837f4c853fa5"},
    {"sc_iso.self" , "3.56" , "d957515b90a80f5b09aee198f8a936c1"},
    {"aim_spu_module.self" , "3.56" , "9e2b7037d86b99ab02d783b7e2e5e8d7"},
    {"spp_verifier.self" , "3.56" , "68fa90750210421aeffbe7bb3f528171"},
    {"mc_iso_spu_module.self" , "3.56" , "6e1cc075abe11a977ed30633a509c24e"},
    {"me_iso_spu_module.self" , "3.56" , "767d5cf6aee8f968b158fe9c2220435b"},
    {"sv_iso_spu_module.self" , "3.56" , "9f96d7e7b885ada4c22f710d95834061"},
    {"sb_iso_spu_module.self" , "3.56" , "e6359fdb5404d429be5ce493169194d2"},
    {"default.spp" , "3.56" , "d061a89fb89ab172937006771812b28a"},
    {"lv1.self" , "3.56" , "d7c539567e486bb22a72c63d19ad42d8"},
    {"lv0" , "3.56" , "393b842d0f725096d49df9ba2b7e4598"},
    {"lv2_kernel.self" , "3.56" , "602acd4b21ad6ac8e894dc8db288c6ab"},
    {"eurus_fw.bin" , "3.56" , "b5f54d9a11d1eae71f35b5907c6b9d3a"},
    {"emer_init.self" , "3.56" , "f90cee182ffa4cf38eecd6fce9168ab1"},
    {"hdd_copy.self" , "3.56" , "d61b975e4c6a241c4b0e9d59882edcf5"},
    {"manu_info_spu_module.self" , "3.56" , "d2e495c8abfa7a2b70e70fe4c67cd764"},
    {"prog.srvk" , "3.56" , "8fe7d21f3bb24e473c4d519df41f2719"},
    {"pkg.srvk" , "3.56" , "53b91522ace809f44d4eea1ee3095f93"},
    // FW 3.60 Files
    {"creserved_0" , "3.60" , "09a1d434dbd7197e7c3af8a7c28ca38b"},
    {"sdk_version" , "3.60" , "4634c0633dc83965f4fb6192c0c0720e"},
    {"spu_pkg_rvk_verifier.self" , "3.60" , "8d206c526af5943020942dcc1f351a74"},
    {"spu_token_processor.self" , "3.60" , "ba8bf9d8c3477ac4d9e96cde01d6d4fb"},
    {"spu_utoken_processor.self" , "3.60" , "4aee9a65bf340cc3860c9fd299885086"},
    {"sc_iso.self" , "3.60" , "3e54d40c05458cae7acd0936942a9657"},
    {"aim_spu_module.self" , "3.60" , "1f972a1f803de63bdbc6ce92ac8fc199"},
    {"spp_verifier.self" , "3.60" , "28c2aa9112d875fc77d907a1658fe94d"},
    {"mc_iso_spu_module.self" , "3.60" , "b4642450399a338282e6355899f98b5b"},
    {"me_iso_spu_module.self" , "3.60" , "079b218624983a1d864b33f2a2a503e3"},
    {"sv_iso_spu_module.self" , "3.60" , "ca61237aa2ef64eaa638badb0c5e7fb1"},
    {"sb_iso_spu_module.self" , "3.60" , "f53f8382a4d2229e0e102b7a64063ca3"},
    {"default.spp" , "3.60" , "7cf807ef5976931e733691b6f5eff7cf"},
    {"lv1.self" , "3.60" , "5735217ec885cd474f062953ae075644"},
    {"lv0" , "3.60" , "3823882072f8e984bc7c9a4aa0254296"},
    {"lv0.2" , "3.60" , "f80bbd2d06ca56b919b5b073c7e53979"},
    {"lv2_kernel.self" , "3.60" , "d03df023ffbb6491d047b7e23236283a"},
    {"eurus_fw.bin" , "3.60" , "b5f54d9a11d1eae71f35b5907c6b9d3a"},
    {"emer_init.self" , "3.60" , "3a5b8431997cc655eec6e08b04ad65cf"},
    {"hdd_copy.self" , "3.60" , "6c4c3ce9aa21864ea64cd9a9ad5e5c7e"},
    {"manu_info_spu_module.self" , "3.60" , "8ec1208585d367bad1d9b89db6b8acf7"},
    {"prog.srvk" , "3.60" , "b86a20657203f03cacfbff3433f8c2a8"},
    {"pkg.srvk" , "3.60" , "f8ba64550c819ea3e2cfba069bd68c67"},
    // FW 3.61 Files
    {"creserved_0" , "3.61" , "09a1d434dbd7197e7c3af8a7c28ca38b"},
    {"sdk_version" , "3.61" , "9c11d208d5f051f0ad762a526b8a1669"},
    {"spu_pkg_rvk_verifier.self" , "3.61" , "532bfab841fc4f5211b3ccba997f78e4"},
    {"spu_token_processor.self" , "3.61" , "fa31caf6e79ae3529d27d4ab02ecfc39"},
    {"spu_utoken_processor.self" , "3.61" , "65131ce2d51ac27cb0f438bdf950e00b"},
    {"sc_iso.self" , "3.61" , "4a12608f5b84a9c3d894c48284231239"},
    {"aim_spu_module.self" , "3.61" , "9ea38d368571d18d5256f6bbb2d116d4"},
    {"spp_verifier.self" , "3.61" , "33161737ceb7d0a93a8752211345a8f1"},
    {"mc_iso_spu_module.self" , "3.61" , "f861d45ef9af1b30fa0cd653e7b15132"},
    {"me_iso_spu_module.self" , "3.61" , "ef6a516f902a30e56c47273c2f78839f"},
    {"sv_iso_spu_module.self" , "3.61" , "75d6f2004d87c3d964e9da5b10a843d1"},
    {"sb_iso_spu_module.self" , "3.61" , "b3adb8a7d3d7b9ecf0aa10dc5e0ec902"},
    {"default.spp" , "3.61" , "2cebe1ace63a58a900c1b41cd12b3913"},
    {"lv1.self" , "3.61" , "0d2ffedebf016a152df44ff415706ba6"},
    {"lv0" , "3.61" , "17f859229c4cf88bebbfbf4d67c6e61c"},
    {"lv0.2" , "3.61" , "a89b8c89772625139a5998505e025141"},
    {"lv2_kernel.self" , "3.61" , "d0be539836f60724b12381879bff5f9e"},
    {"eurus_fw.bin" , "3.61" , "b5f54d9a11d1eae71f35b5907c6b9d3a"},
    {"emer_init.self" , "3.61" , "6e075ac06fa824661bed8e920b78bce1"},
    {"hdd_copy.self" , "3.61" , "158028b2b6fd360a4f6256d6af901298"},
    {"manu_info_spu_module.self" , "3.61" , "85f37e7534c1f1a13d979393a8831b48"},
    {"prog.srvk" , "3.61" , "35dd53916cf44721c0ce9179bc27b367"},
    {"pkg.srvk" , "3.61" , "b50d9e45e8fc42aacdda82ec93edc11a"},
    // FW 3.66 Files
    {"creserved_0" , "3.66" , "09a1d434dbd7197e7c3af8a7c28ca38b"},
    {"sdk_version" , "3.66" , "e005c64998dc504139fc6b6bcb2a60be"},
    {"spu_pkg_rvk_verifier.self" , "3.66" , "a6c8a9d22a85c64d543b786e276b4136"},
    {"spu_token_processor.self" , "3.66" , "b9b603beb19cffc1653f2cb4e3dbe039"},
    {"spu_utoken_processor.self" , "3.66" , "3ffa720657a37ade5cf8e05c5ae051ec"},
    {"sc_iso.self" , "3.66" , "998435ea75f039525f05dae61562d672"},
    {"aim_spu_module.self" , "3.66" , "6ee5c59843e1a687cab2408327943afb"},
    {"spp_verifier.self" , "3.66" , "38ea95055da2fefe757392f5fe8c687a"},
    {"mc_iso_spu_module.self" , "3.66" , "b59a05ebcaf1f59f7ebea7eb409294ef"},
    {"me_iso_spu_module.self" , "3.66" , "8611ffcc6812ecff458a3acd9678cb4a"},
    {"sv_iso_spu_module.self" , "3.66" , "71b865a86463f181f39dfa18ea22ab51"},
    {"sb_iso_spu_module.self" , "3.66" , "ca63c12dc5525987fd2f9f07d6018bf1"},
    {"default.spp" , "3.66" , "f1823613691ebc53fb9c1f8aa89ac9fc"},
    {"lv1.self" , "3.66" , "39768155ce81ead2e8a72fe2d4732a7e"},
    {"lv0" , "3.66" , "154e3493ca5cc4d0dd3b587b9748551c"},
    {"lv0.2" , "3.66" , "98f43409d1cd91f32c24164f9fd70b93"},
    {"lv2_kernel.self" , "3.66" , "68d59de436701b2a9b04158116387ce5"},
    {"eurus_fw.bin" , "3.66" , "b5f54d9a11d1eae71f35b5907c6b9d3a"},
    {"emer_init.self" , "3.66" , "0749135d85d0f5b67e107d9bec4f513f"},
    {"hdd_copy.self" , "3.66" , "0cfb5d65cb4a30440175ad6f8ad98a5f"},
    {"manu_info_spu_module.self" , "3.66" , "ef46bbcd6a8405305bec3ae0a7fcb410"},
    {"prog.srvk" , "3.66" , "c6e142fff29f5dacdbbf56779c0f32c7"},
    {"pkg.srvk" , "3.66" , "4a19dbb451063fc27b23aac4f377ab3a"},
    // FW 3.70 Files
    {"creserved_0" , "3.70" , "09a1d434dbd7197e7c3af8a7c28ca38b"},
    {"sdk_version" , "3.70" , "fcc0998c9f202d36eba18cebab6b915c"},
    {"spu_pkg_rvk_verifier.self" , "3.70" , "299f1749ab83462368a51116dbc38e1a"},
    {"spu_token_processor.self" , "3.70" , "d2a1b86d18b1bc446e1340d367fe3dcb"},
    {"spu_utoken_processor.self" , "3.70" , "9bb495f34896f163648704b16738fceb"},
    {"sc_iso.self" , "3.70" , "309f0f052cbf85b3b52b0a7085ad1bf8"},
    {"aim_spu_module.self" , "3.70" , "caa748e4c7aa6306bfd20d528e5901d4"},
    {"spp_verifier.self" , "3.70" , "439af92e9a8f33bab4b3c8bb7313e726"},
    {"mc_iso_spu_module.self" , "3.70" , "478beaae4f24e8f2865f75ae48803ba4"},
    {"me_iso_spu_module.self" , "3.70" , "35f2a71dfd7a2b372f70eda000fae302"},
    {"sv_iso_spu_module.self" , "3.70" , "a897b926651ea77efa8a6e13c112f2f0"},
    {"sb_iso_spu_module.self" , "3.70" , "bd1c1840b5a43da218e28725fe7425bb"},
    {"me_iso_for_ps2emu.self" , "3.70" , "76c5f4b46ffcc8e5108f07d4848e403c"},
    {"sv_iso_for_ps2emu.self" , "3.70" , "786ead8522e40acbc1ae2b43bfe2091a"},
    {"default.spp" , "3.70" , "29b8206871658ceb94114c6ebe051cdf"},
    {"lv1.self" , "3.70" , "9633eb48774a55af646f0e9459c193ee"},
    {"lv0" , "3.70" , "00941d7ed5a4fc13b98b89edebe05d7a"},
    {"lv0.2" , "3.70" , "d31a17095353508c43e3035d05db2b7c"},
    {"lv2_kernel.self" , "3.70" , "2339b25eba47ca07ce7064a8eb5b6328"},
    {"eurus_fw.bin" , "3.70" , "b5f54d9a11d1eae71f35b5907c6b9d3a"},
    {"emer_init.self" , "3.70" , "cfd1f37896112f1399ce02abefaae839"},
    {"hdd_copy.self" , "3.70" , "ae890b2b996ca54e5d919353411f6be9"},
    {"manu_info_spu_module.self" , "3.70" , "4746ac87c97caaf2225bae432b813142"},
    {"prog.srvk" , "3.70" , "6c5884658da2d12d41d5f7a1f690792a"},
    {"pkg.srvk" , "3.70" , "d0df4a905bafb3464ec47784c884c7f2"},
    // FW 3.72 Files
    {"creserved_0" , "3.72" , "09a1d434dbd7197e7c3af8a7c28ca38b"},
    {"sdk_version" , "3.72" , "9496940bc3cbab8e06cdb8da1a8fb0b3"},
    {"spu_pkg_rvk_verifier.self" , "3.72" , "70cc06c9c4e2b7dec397425065020ba4"},
    {"spu_token_processor.self" , "3.72" , "2ef1679656908524f65926932d85b8b3"},
    {"spu_utoken_processor.self" , "3.72" , "93f715db4499344e72315290a00014d3"},
    {"sc_iso.self" , "3.72" , "f89ebc0f8270d651d3143a4aab696b4b"},
    {"aim_spu_module.self" , "3.72" , "c5038fba00845cce9b9e61ecb15dd7b6"},
    {"spp_verifier.self" , "3.72" , "1ee8070323e165ea687aaf9fe9002f61"},
    {"mc_iso_spu_module.self" , "3.72" , "a71fcc4f3b33b009a21bf44926348694"},
    {"me_iso_spu_module.self" , "3.72" , "9eed10fa460da1731319adffae848455"},
    {"sv_iso_spu_module.self" , "3.72" , "4913b8c9f264badf81bcd8f53f9257f4"},
    {"sb_iso_spu_module.self" , "3.72" , "d2e97f0c6e2fcda18f94bc8e9241c90b"},
    {"me_iso_for_ps2emu.self" , "3.72" , "066d2a3f7ed4670667b6402ff5f1741c"},
    {"sv_iso_for_ps2emu.self" , "3.72" , "5235e2ad69fb63d311717de441ff7b6e"},
    {"default.spp" , "3.72" , "a88c5ba3789cb5fe569d416d24123ff0"},
    {"lv1.self" , "3.72" , "78e101c6217edb7e0eaab48d0edce4d2"},
    {"lv0" , "3.72" , "874735cb93f13db523dd094adc132cc3"},
    {"lv0.2" , "3.72" , "604b42a216e8833936d061aad16f1e77"},
    {"lv2_kernel.self" , "3.72" , "505f908b7ac2c403d264e54b506132d5"},
    {"eurus_fw.bin" , "3.72" , "b5f54d9a11d1eae71f35b5907c6b9d3a"},
    {"emer_init.self" , "3.72" , "47c5fc6d298fb7404646561d8b887a5c"},
    {"hdd_copy.self" , "3.72" , "e2c5d2dcfee8c83c2b7b4bdcdfac186f"},
    {"manu_info_spu_module.self" , "3.72" , "b2e08dc15d8c5b836731ae910f63ba19"},
    {"prog.srvk" , "3.72" , "36fc5e86fde1b59af91af0e66cc1542b"},
    {"pkg.srvk" , "3.72" , "540438ca195f4e21fddf68d6de273db7"},
    // FW 3.73 Files
    {"creserved_0" , "3.73" , "09a1d434dbd7197e7c3af8a7c28ca38b"},
    {"sdk_version" , "3.73" , "73447ecd4e8cbda29eb45280328819fe"},
    {"spu_pkg_rvk_verifier.self" , "3.73" , "30c714f4df3fb9ab75985681a10ebe0b"},
    {"spu_token_processor.self" , "3.73" , "04263c5a19ea73cbf9407182c1ac14db"},
    {"spu_utoken_processor.self" , "3.73" , "2e7e5011effe3e1f1776070bf56e9feb"},
    {"sc_iso.self" , "3.73" , "96ef49cf824dcdf09f819e69a9d3dfe0"},
    {"aim_spu_module.self" , "3.73" , "cd50b269ed72d5c10a9c2889a8999257"},
    {"spp_verifier.self" , "3.73" , "5fc96e3414f3c4e37fe603841157cc93"},
    {"mc_iso_spu_module.self" , "3.73" , "7109b4f4b279bd82371d3e3b295b5f1f"},
    {"me_iso_spu_module.self" , "3.73" , "484365b64caa636e60c3aa98efa518e1"},
    {"sv_iso_spu_module.self" , "3.73" , "b254fd4beae454fba4cf04fa3c667ccb"},
    {"sb_iso_spu_module.self" , "3.73" , "da21a9ade71c8232a68d9de779ca8c32"},
    {"me_iso_for_ps2emu.self" , "3.73" , "154d78cdb0e326b86d6754dbe1edb948"},
    {"sv_iso_for_ps2emu.self" , "3.73" , "cdaa4f89bc2363d34530eaf6bb1e2281"},
    {"default.spp" , "3.73" , "bd89984b493ece385da32bd768fdfc9f"},
    {"lv1.self" , "3.73" , "894dd7454aa096bcc769da56c2d4c0e0"},
    {"lv0" , "3.73" , "6fcbc48b65aac48c902629a18286d943"},
    {"lv0.2" , "3.73" , "d4c1596bcc14d1d5da9169e6f2c93120"},
    {"lv2_kernel.self" , "3.73" , "5b45121f6e3e9dfab7ad0765e5d6a14a"},
    {"eurus_fw.bin" , "3.73" , "b5f54d9a11d1eae71f35b5907c6b9d3a"},
    {"emer_init.self" , "3.73" , "b7fa8a82b3865b7dc830ccb8a34595aa"},
    {"hdd_copy.self" , "3.73" , "3c47d0a4fa0e78264694d8f48b94ac66"},
    {"manu_info_spu_module.self" , "3.73" , "22addd8cea03cabf3052d7c182c68ccf"},
    {"prog.srvk" , "3.73" , "03bbb883afaace43fdaccac4efea8e74"},
    {"pkg.srvk" , "3.73" , "fa0976f212c7b270d25cbbf284e89ae0"},
    // FW 4.00 Files
    {"creserved_0"               , "4.00" , "09a1d434dbd7197e7c3af8a7c28ca38b"},
    {"sdk_version"               , "4.00" , "e67a4d209bbdee902e8e7a3f48931b71"},
    {"spu_pkg_rvk_verifier.self" , "4.00" , "7fb7b15f9a1e7bf735f6b23edde2a0ee"},
    {"spu_token_processor.self"  , "4.00" , "ef9c94719c4d6734603c6cda456c15f0"},
    {"spu_utoken_processor.self" , "4.00" , "3864fd2937e166d9c5506f231049fc58"},
    {"sc_iso.self"               , "4.00" , "97170ae9accd8c5f963f7a95aeeae89b"},
    {"aim_spu_module.self"       , "4.00" , "1473acf31ef71b111f8563218e08d2b3"},
    {"spp_verifier.self"         , "4.00" , "f53b9fba1c4663c2d65715705b7e3a98"},
    {"mc_iso_spu_module.self"    , "4.00" , "3744b53626c0b7dac84e0331f1fc9211"},
    {"me_iso_spu_module.self"    , "4.00" , "b0f0daaf7acc37031a640e70e40dbab2"},
    {"sv_iso_spu_module.self"    , "4.00" , "6307e959ccc862298033a28e96dfcd27"},
    {"sb_iso_spu_module.self"    , "4.00" , "a89fdb4dabbcf2e3cbfa0585eddce370"},
    {"me_iso_for_ps2emu.self"    , "4.00" , "e59a8048346506c8c94165704bf086e1"},
    {"sv_iso_for_ps2emu.self"    , "4.00" , "c57067f62bb5ead2175062f0ffd373ab"},
    {"default.spp"               , "4.00" , "559a9eb15641989adb22c1a3b017dce2"},
    {"lv1.self"                  , "4.00" , "ea98b19492ca78e9dd9cfe9b26a3f66a"},
    {"lv0"                       , "4.00" , "c38ac278229f0b678b300e711fc79efd"},
    {"lv0.2"                     , "4.00" , "0ff7584f806a4d89780e3c489713489a"},
    {"lv2_kernel.self"           , "4.00" , "91132793ef9e11693109cbb110ac4aa2"},
    {"eurus_fw.bin"              , "4.00" , "b5f54d9a11d1eae71f35b5907c6b9d3a"},
    {"emer_init.self"            , "4.00" , "634690713f08d6352dae111e938fdb64"},
    {"hdd_copy.self"             , "4.00" , "40a867a0c19e04bfcebf53dcb335c7a6"},
    {"manu_info_spu_module.self" , "4.00" , "19102d74d8388b80c05fdd5cb384b02f"},
    {"prog.srvk"                 , "4.00" , "a4ca1ad225c64055fba3ccd6518701a6"},
    {"pkg.srvk"                  , "4.00" , "cae7968c1cf9f7a8d01ad60c58535c67"},
    // FW 4.10 Files
    {"creserved_0" , "4.10" , "09a1d434dbd7197e7c3af8a7c28ca38b"},
    {"sdk_version" , "4.10" , "0d9cd8e0e43f23e31d441b22bf46ef08"},
    {"spu_pkg_rvk_verifier.self" , "4.10" , "22234913192677d47fa0e2be8f0c92d4"},
    {"spu_token_processor.self" , "4.10" , "ca65a513f5ef6386cec04f8905887c76"},
    {"spu_utoken_processor.self" , "4.10" , "cdb8132dfbc00b4ad4e71a24c6e2e819"},
    {"sc_iso.self" , "4.10" , "a793201762a3fe35dec4a5f702d9f2dc"},
    {"aim_spu_module.self" , "4.10" , "ebbd103489ac59e25625c30de3146eda"},
    {"spp_verifier.self" , "4.10" , "173e958b5d8e8dcead291367d98b30b3"},
    {"mc_iso_spu_module.self" , "4.10" , "61eaf194b1b8f3bba8bbc95365107f43"},
    {"me_iso_spu_module.self" , "4.10" , "ee554afad3e3977c45162859e83b58a5"},
    {"sv_iso_spu_module.self" , "4.10" , "0120379b8a947ab676646cc8e4247734"},
    {"sb_iso_spu_module.self" , "4.10" , "88634125e5f3f65c949372a9369d2b74"},
    {"me_iso_for_ps2emu.self" , "4.10" , "cb23375ab6ea359b2b4b35ee8b9b76d4"},
    {"sv_iso_for_ps2emu.self" , "4.10" , "d63c82f101b17e131a522ee4fce9bacd"},
    {"default.spp" , "4.10" , "d8816389c27ec666558b712b7b1d5726"},
    {"lv1.self" , "4.10" , "a768a6096afe1012bc0976b4ef1be62e"},
    {"lv0" , "4.10" , "e69d27ee63acacb0ab925e4f1073e18e"},
    {"lv0.2" , "4.10" , "6ab2f344eedab7d6c2a25ab36777f096"},
    {"lv2_kernel.self" , "4.10" , "1f0a9474293a9671c054c106a71329e5"},
    {"eurus_fw.bin" , "4.10" , "fde1f0429ac816635656a71b2f2a95c7"},
    {"emer_init.self" , "4.10" , "edf767a4d8a77d30350d4296345817a9"},
    {"hdd_copy.self" , "4.10" , "bd823871906c3b0315e8553b2735b4c7"},
    {"manu_info_spu_module.self" , "4.10" , "39928662e23c332453aeaae176cc8b5c"},
    {"prog.srvk" , "4.10" , "8642c7891ea6a3d906619ee0e68cbd9a"},
    {"pkg.srvk" , "4.10" , "06e8a27f3ca603e686b0bb0c03830d70"},
    // FW 4.11 Files
    {"creserved_0" , "4.11" , "09a1d434dbd7197e7c3af8a7c28ca38b"},
    {"sdk_version" , "4.11" , "55d6329a236ed0688f265b743b36a574"},
    {"spu_pkg_rvk_verifier.self" , "4.11" , "aab4e36f96cbc38f467916da90cbef50"},
    {"spu_token_processor.self" , "4.11" , "22a2421b0480c8b84035cd033ed5ce5c"},
    {"spu_utoken_processor.self" , "4.11" , "8cf2d3540a23145d62bd769edb77bedf"},
    {"sc_iso.self" , "4.11" , "e574ecd6a390c897109dca694e60acc1"},
    {"aim_spu_module.self" , "4.11" , "94ff8362cf30c910fa24dbf673b9f54b"},
    {"spp_verifier.self" , "4.11" , "74888b1b3be6167446dd8889f9578e88"},
    {"mc_iso_spu_module.self" , "4.11" , "ac08b9d1c0e149db8ff1f431f0fd0adf"},
    {"me_iso_spu_module.self" , "4.11" , "eabc2fccb6a55379899f15840186bc40"},
    {"sv_iso_spu_module.self" , "4.11" , "0bc9354572d05d51486f22f9a3d978d0"},
    {"sb_iso_spu_module.self" , "4.11" , "a42aab01a041244e942e2fe41ecb8ac1"},
    {"me_iso_for_ps2emu.self" , "4.11" , "953ff19ccae42f8f968a254e0aab121d"},
    {"sv_iso_for_ps2emu.self" , "4.11" , "699117b7ed1316e224962315699e0548"},
    {"default.spp" , "4.11" , "5d97e236ca63742334fe5f4c27310e30"},
    {"lv1.self" , "4.11" , "a523b2f347a8ed163762272f0be36679"},
    {"lv0" , "4.11" , "b8b1b877a986829250f4aeb8fa659eb9"},
    {"lv0.2" , "4.11" , "9f2af0c15e675c0b050a54a40b098c7a"},
    {"lv2_kernel.self" , "4.11" , "80c625e852153e01515e520c127c9bfb"},
    {"eurus_fw.bin" , "4.11" , "b5f54d9a11d1eae71f35b5907c6b9d3a"},
    {"emer_init.self" , "4.11" , "93131fedb860bb54c797d6ddaa03a234"},
    {"hdd_copy.self" , "4.11" , "c85aaba6d749f06dd8185438618f06e1"},
    {"manu_info_spu_module.self" , "4.11" , "4770e1703b1e89e4e6e50d45ab7dedb7"},
    {"prog.srvk" , "4.11" , "0a8a749721f6743d059648ed6ba7cab1"},
    {"pkg.srvk" , "4.11" , "2393bf1493ad556654628f3344af9024"},
    // FW 4.20 Files
    {"creserved_0" , "4.20" , "09a1d434dbd7197e7c3af8a7c28ca38b"},
    {"sdk_version" , "4.20" , "6061903c18588cc21378e51eeb2486e3"},
    {"spu_pkg_rvk_verifier.self" , "4.20" , "b37640a823bf99a3d8ed8648ed794775"},
    {"spu_token_processor.self" , "4.20" , "fb24d926795bd6699f4be223503584c8"},
    {"spu_utoken_processor.self" , "4.20" , "c9941767fb71452cc0938176551d093b"},
    {"sc_iso.self" , "4.20" , "10b2b7605a12fc6b3484610a4c69b088"},
    {"aim_spu_module.self" , "4.20" , "e636c4b8c3d651e1eb6da12aea36719b"},
    {"spp_verifier.self" , "4.20" , "46583eb70bf1d74ba9814b509909578c"},
    {"mc_iso_spu_module.self" , "4.20" , "347291873b2abb08beff50029e168a62"},
    {"me_iso_spu_module.self" , "4.20" , "bb3d836abf3326ecfef4ac3a508995eb"},
    {"sv_iso_spu_module.self" , "4.20" , "ed014c7fd47946cb41ace5687e4d4e63"},
    {"sb_iso_spu_module.self" , "4.20" , "a8d6110cbbbe9b5818a1ca1a29d3e4d2"},
    {"me_iso_for_ps2emu.self" , "4.20" , "64bb4664de4fedb65f2cd1a1d4110372"},
    {"sv_iso_for_ps2emu.self" , "4.20" , "b5461eabca41f893d172f86a3207bc26"},
    {"default.spp" , "4.20" , "f309ca445ede1618a3cea90212ee9556"},
    {"lv1.self" , "4.20" , "e6c23ff9fc968339588b3ef92458d9a5"},
    {"lv0" , "4.20" , "169decc996efa6e43444fefcc9a14741"},
    {"lv0.2" , "4.20" , "59fd7f5325c91eec8bb48fdb1cea769f"},
    {"lv2_kernel.self" , "4.20" , "31b94d71acf15a6bdb5859d20e2e1cad"},
    {"eurus_fw.bin" , "4.20" , "b5f54d9a11d1eae71f35b5907c6b9d3a"},
    {"emer_init.self" , "4.20" , "6516d84d687b937a11903819db0fe20f"},
    {"hdd_copy.self" , "4.20" , "79aad3b730273c13b576af900745a9cb"},
    {"manu_info_spu_module.self" , "4.20" , "c07093bef106ee5cd1c118421964b2d9"},
    {"prog.srvk" , "4.20" , "49e66bf358f6fe758bc86eaad7252329"},
    {"pkg.srvk" , "4.20" , "537b649786646c382d01b5df7dc66cf9"},
    // FW 4.21 Files
    {"creserved_0" , "4.21" , "09a1d434dbd7197e7c3af8a7c28ca38b"},
    {"sdk_version" , "4.21" , "dfa57876b24fc22271beb5ac8937e924"},
    {"spu_pkg_rvk_verifier.self" , "4.21" , "1cdadcdfd160d79dbddbac1caecd12bd"},
    {"spu_token_processor.self" , "4.21" , "a8a53e6d1d7cc28078f99c1f519c5137"},
    {"spu_utoken_processor.self" , "4.21" , "f2a59e52dd948322d2639b6f03b91a9d"},
    {"sc_iso.self" , "4.21" , "decf5b1f722de5c53a34c4158cbe0899"},
    {"aim_spu_module.self" , "4.21" , "d60a539456242bf009ccdd3ed6f21336"},
    {"spp_verifier.self" , "4.21" , "580f02eb1b82b87ae9665f0516bb0cab"},
    {"mc_iso_spu_module.self" , "4.21" , "01e4e6278bc28848b1baeec701d55283"},
    {"me_iso_spu_module.self" , "4.21" , "70d3b68e0c728207406d480e4a3656fc"},
    {"sv_iso_spu_module.self" , "4.21" , "557eafdf7e797ea7171dea9641374e5d"},
    {"sb_iso_spu_module.self" , "4.21" , "ec8cda8e16fb208d76ac299660e4135e"},
    {"me_iso_for_ps2emu.self" , "4.21" , "b08d78746b93476fb5ad90d38ec930b3"},
    {"sv_iso_for_ps2emu.self" , "4.21" , "40c7028bb76300e8be1a467e7e491c3f"},
    {"default.spp" , "4.21" , "6f44bf83b6137567002d22feb059499b"},
    {"lv1.self" , "4.21" , "d9f7a57ed93e336bfcc6b3c10d1018da"},
    {"lv0" , "4.21" , "4ddeb486e7f07af0558947760b9928eb"},
    {"lv0.2" , "4.21" , "e96ddfbe233480c63eec6a92e9fd2ed5"},
    {"lv2_kernel.self" , "4.21" , "78aec0f582573c5f75c5972cb473ad87"},
    {"eurus_fw.bin" , "4.21" , "b5f54d9a11d1eae71f35b5907c6b9d3a"},
    {"emer_init.self" , "4.21" , "e84d7fa526f13ddc259a860b021ce64f"},
    {"hdd_copy.self" , "4.21" , "a3232ff40d3cb50488c90911db286d8a"},
    {"manu_info_spu_module.self" , "4.21" , "2dbadc4a2dceac35f69a8e445491734d"},
    {"prog.srvk" , "4.21" , "eda9941c84763bb26bf975a579676eb9"},
    {"pkg.srvk" , "4.21" , "6c220eab62dbec0a14e0c329ae1d700d"},
    // FW 4.25 Files
    {"creserved_0" , "4.25" , "09a1d434dbd7197e7c3af8a7c28ca38b"},
    {"sdk_version" , "4.25" , "a01b32cd2b1e29fa0351fbe1bc1b986f"},
    {"spu_pkg_rvk_verifier.self" , "4.25" , "28f7dbb9dfcc64cbfc31d065a476dad4"},
    {"spu_token_processor.self" , "4.25" , "ae8e4a8f29b78d62e3fa72eb32ccf3e2"},
    {"spu_utoken_processor.self" , "4.25" , "b9fb697c1fe64b0c3323af0b860331f3"},
    {"sc_iso.self" , "4.25" , "71be4c9d062ad3fe682f51467788f39b"},
    {"aim_spu_module.self" , "4.25" , "e3d1c5125f080490955c938511855482"},
    {"spp_verifier.self" , "4.25" , "678e330a794a04952c553810be4a824d"},
    {"mc_iso_spu_module.self" , "4.25" , "e2bd05a2ea6d0fe4ba8afc77f508af75"},
    {"me_iso_spu_module.self" , "4.25" , "d4458d316c7f77f426ea98a560feb689"},
    {"sv_iso_spu_module.self" , "4.25" , "9a34120704c08358e6ecac560f4ea7b1"},
    {"sb_iso_spu_module.self" , "4.25" , "94b668d9964d39f0ffffa2532e9290d3"},
    {"me_iso_for_ps2emu.self" , "4.25" , "5f3705a9a4b9cd0d33303623dfd02220"},
    {"sv_iso_for_ps2emu.self" , "4.25" , "23be2713ab61ccd9fe946f2894be3d02"},
    {"default.spp" , "4.25" , "88c5c6fa11bd34c2155f58faf5b84a89"},
    {"lv1.self" , "4.25" , "09f6daca862850e57906f305a320f95d"},
    {"lv0" , "4.25" , "2fd2cf54908aee6884aac2eab4cfda86"},
    {"lv0.2" , "4.25" , "2e665676f2e9b1d95c5c745e7d7a5339"},
    {"lv2_kernel.self" , "4.25" , "0af3fb68187c9599c1da7dcadc903601"},
    {"eurus_fw.bin" , "4.25" , "b5f54d9a11d1eae71f35b5907c6b9d3a"},
    {"emer_init.self" , "4.25" , "62073b10b22126fa539e4aea2bd34816"},
    {"hdd_copy.self" , "4.25" , "168612c5a0fea5517c04bb244c4074c9"},
    {"manu_info_spu_module.self" , "4.25" , "4e05177e68b51cd50e868abffc336269"},
    {"prog.srvk" , "4.25" , "1085132297e8fa266aeae703a15858ed"},
    {"pkg.srvk" , "4.25" , "238bc014ce0482718fb7b0ad1e0fac7f"},
    // FW 4.30 Files
    {"aim_spu_module.self" , "4.30" , "667fc8db8e5519cacbf8f9f2af2e0b08"},
    {"creserved_0" , "4.30" , "09a1d434dbd7197e7c3af8a7c28ca38b"},
    {"default.spp" , "4.30" , "5cbf8d6fa103c32e8ea94e841d908a13"},
    {"emer_init.self" , "4.30" , "3e9606f2312708e179bc9fabd4824746"},
    {"eurus_fw.bin" , "4.30" , "b5f54d9a11d1eae71f35b5907c6b9d3a"},
    {"hdd_copy.self" , "4.30" , "26b786c982ff62686e0f5d0bebe4ba85"},
    {"lv0" , "4.30" , "84d2cfffc6c85724374af43c67833793"},
    {"lv0.2" , "4.30" , "6557df35f9a5446c4340815f45c67cc7"},
    {"lv1.self" , "4.30" , "2b25f94a437653288fdaef00f01eeddd"},
    {"lv2_kernel.self" , "4.30" , "6972dc45ce36186e0ecc13d6d54e2db6"},
    {"manu_info_spu_module.self" , "4.30" , "559996552d855c5b6386d8ef99134051"},
    {"mc_iso_spu_module.self" , "4.30" , "2cb801dbf76fd3c83dfe01d6ff99e824"},
    {"me_iso_for_ps2emu.self" , "4.30" , "c79e5c952d4bf8208668788ab85a019f"},
    {"me_iso_spu_module.self" , "4.30" , "0e6248204d381be2c21b0630aa7a432d"},
    {"pkg.srvk" , "4.30" , "d5a194af4965159101619370e2989e9c"},
    {"prog.srvk" , "4.30" , "846119d645909060a441f475fbe438d0"},
    {"sb_iso_spu_module.self" , "4.30" , "13e53d2ec13f91b3c5b0acfd076c5391"},
    {"sc_iso.self" , "4.30" , "5a6afcca39bed9e979b2eadd46d516e1"},
    {"sdk_version" , "4.30" , "5658fe830dd262d5692fe7f3dc3d723a"},
    {"spp_verifier.self" , "4.30" , "fc0d132faee4585963887860c33807f1"},
    {"spu_pkg_rvk_verifier.self" , "4.30" , "ce1cecf9844cb17b5afe5fa738d564f4"},
    {"spu_token_processor.self" , "4.30" , "05f02eca781c7462870e4a80a13e6a76"},
    {"spu_utoken_processor.self" , "4.30" , "20054c84a4bf7e1237fdaf645101ef74"},
    {"sv_iso_for_ps2emu.self" , "4.30" , "8073e364721ebec9af8082c9a12ff796"},
    {"sv_iso_spu_module.self" , "4.30" , "b95d9a045a89dc1cbca94fd3bb6e91f1"},
    // FW 4.31 Files
    {"creserved_0" , "4.31" , "69172603b8621a6e8cb71a698fd921c4"},
    {"sdk_version" , "4.31" , "737fb2ca5ba8d4f9a57c4fc1f1687f12"},
    {"spu_pkg_rvk_verifier.self" , "4.31" , "0249a9bcc68324076c2df6b90ed357b8"},
    {"spu_token_processor.self" , "4.31" , "15ced1cd4ede0b93e6462aa7906d4b26"},
    {"spu_utoken_processor.self" , "4.31" , "b27d3597ec55097658774d74f279771c"},
    {"sc_iso.self" , "4.31" , "847c8504bed50a3e7972366b5c61206a"},
    {"aim_spu_module.self" , "4.31" , "b5b239f497312162f8fe76b8950db102"},
    {"spp_verifier.self" , "4.31" , "1c0b77fdaa68712be07903c45094bd84"},
    {"mc_iso_spu_module.self" , "4.31" , "ced13cd98d03a9169160b4987f9de870"},
    {"me_iso_spu_module.self" , "4.31" , "8aefc1e5bc809f457dd2367b74fbcd72"},
    {"sv_iso_spu_module.self" , "4.31" , "47ca0cda845e68e939a16e341b59c014"},
    {"sb_iso_spu_module.self" , "4.31" , "6b44d91221fbbdbb26ae422869ed4cbc"},
    {"me_iso_for_ps2emu.self" , "4.31" , "69f29a65c675f81590cbeac9191225af"},
    {"sv_iso_for_ps2emu.self" , "4.31" , "91dc8c1ef2d1daa213401673188aeee7"},
    {"default.spp" , "4.31" , "1f342c5d9c197cd72fcb3fa020ed6e14"},
    {"lv1.self" , "4.31" , "748259d883f273ba0e7a076f7a7d932a"},
    {"lv0" , "4.31" , "d787a4498c0798c4b55a688b9843bacb"},
    {"lv0.2" , "4.31" , "e06846301d65cd2e9c1829cfd2eaf47e"},
    {"lv2_kernel.self" , "4.31" , "b2dd13286198a6375f2878fc9b9e304f"},
    {"eurus_fw.bin" , "4.31" , "b5f54d9a11d1eae71f35b5907c6b9d3a"},
    {"emer_init.self" , "4.31" , "e33dcaa639b4ddcdb2e310787e9e53bd"},
    {"hdd_copy.self" , "4.31" , "f825f0ddab99e1d574f50c9a95f61b60"},
    {"manu_info_spu_module.self" , "4.31" , "e758c185481c6ac74e8b73a8ff684871"},
    {"prog.srvk" , "4.31" , "b4b38147dae1929e375e3be6fcacee58"},
    {"pkg.srvk" , "4.31" , "bfddccae3ec6e22efd9b1f2fe4694a14"},
    {NULL, NULL, NULL}
};
