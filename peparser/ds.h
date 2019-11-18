#pragma once
// Machine Types
// The Machine field has one of the following values that specifies its CPU type.An image file can be run only on the specified machine or on a system that emulates the specified machine.

// Constant	Value	Description
#define NUMBER_OF_MACHINE_TYPES 25
#define NUMBER_OF_IFH_CHARACTERISTICS 15
#define NUMBER_OF_DLL_CHARACTERISTICS 15
#define NUMBER_OF_SECTION_CHARACTERISTICS 41
#define NUMBER_OF_DATA_DIRECTORY_ENTRIES 16

unsigned long ifh_machines[NUMBER_OF_MACHINE_TYPES] = {
0x0		, // IMAGE_FILE_MACHINE_UNKNOWN		// The contents of this field are assumed to be applicable to any machine type	
0x1d3	, // IMAGE_FILE_MACHINE_AM33		// Matsushita AM33	
0x8664	, // IMAGE_FILE_MACHINE_AMD64		// x64	
0x1c0	, // IMAGE_FILE_MACHINE_ARM			// ARM little endian	
0xaa64	, // IMAGE_FILE_MACHINE_ARM64		// ARM64 little endian	
0x1c4	, // IMAGE_FILE_MACHINE_ARMNT		// ARM Thumb-2 little endian	
0xebc	, // IMAGE_FILE_MACHINE_EBC			// EFI byte code	
0x14c	, // IMAGE_FILE_MACHINE_I386		// Intel 386 or later processors and compatible processors	
0x200	, // IMAGE_FILE_MACHINE_IA64		// Intel Itanium processor family	
0x9041	, // IMAGE_FILE_MACHINE_M32R		// Mitsubishi M32R little endian	
0x266	, // IMAGE_FILE_MACHINE_MIPS16		// MIPS16	
0x366	, // IMAGE_FILE_MACHINE_MIPSFPU		// MIPS with FPU	
0x466	, // IMAGE_FILE_MACHINE_MIPSFPU16	// MIPS16 with FPU	
0x1f0	, // IMAGE_FILE_MACHINE_POWERPC		// Power PC little endian	
0x1f1	, // IMAGE_FILE_MACHINE_POWERPCFP	// Power PC with floating point support	
0x166	, // IMAGE_FILE_MACHINE_R4000		// MIPS little endian	
0x5032	, // IMAGE_FILE_MACHINE_RISCV32		// RISC-V 32-bit address space	
0x5064	, // IMAGE_FILE_MACHINE_RISCV64		// RISC-V 64-bit address space	
0x5128	, // IMAGE_FILE_MACHINE_RISCV128	// RISC-V 128-bit address space	
0x1a2	, // IMAGE_FILE_MACHINE_SH3			// Hitachi SH3	
0x1a3	, // IMAGE_FILE_MACHINE_SH3DSP		// Hitachi SH3 DSP	
0x1a6	, // IMAGE_FILE_MACHINE_SH4			// Hitachi SH4	
0x1a8	, // IMAGE_FILE_MACHINE_SH5			// Hitachi SH5	
0x1c2	, // IMAGE_FILE_MACHINE_THUMB		// Thumb	
0x169	, // IMAGE_FILE_MACHINE_WCEMIPSV2	// MIPS little-endian WCE v2
};

typedef struct _IFH_CHARACTERISTICS
{
	int value;
	const char *flagName;
	bool isActive;
} IFH_CHARACTERISTICS;

IFH_CHARACTERISTICS ifh_characteristics[NUMBER_OF_IFH_CHARACTERISTICS] = {
{ 0x0001, "IMAGE_FILE_RELOCS_STRIPPED",				false },	// Image only, Windows CE, and Microsoft Windows NT and later.This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address.If the base address is not available, the loader reports an error.The default behavior of the linker is to strip base relocations from executable(EXE) files.
{ 0x0002, "IMAGE_FILE_EXECUTABLE_IMAGE",			false },	// Image only.This indicates that the image file is valid and can be run.If this flag is not set, it indicates a linker error.
{ 0x0004, "IMAGE_FILE_LINE_NUMS_STRIPPED",			false },	// COFF line numbers have been removed.This flag is deprecated and should be zero.
{ 0x0008, "IMAGE_FILE_LOCAL_SYMS_STRIPPED",			false },	// COFF symbol table entries for local symbols have been removed.This flag is deprecated and should be zero.
{ 0x0010, "IMAGE_FILE_AGGRESSIVE_WS_TRIM",			false },	// Obsolete.Aggressively trim working set.This flag is deprecated for Windows 2000 and later and must be zero.
{ 0x0020, "IMAGE_FILE_LARGE_ADDRESS_ AWARE",		false },	// Application can handle > 2 - GB addresses.	0x0040	This flag is reserved for future use.
{ 0x0080, "IMAGE_FILE_BYTES_REVERSED_LO",			false },	// Little endian : the least significant bit(LSB) precedes the most significant bit(MSB) in memory.This flag is deprecated and should be zero.
{ 0x0100, "IMAGE_FILE_32BIT_MACHINE",				false },	// Machine is based on a 32 - bit - word architecture.
{ 0x0200, "IMAGE_FILE_DEBUG_STRIPPED",				false },	// Debugging information is removed from the image file.
{ 0x0400, "IMAGE_FILE_REMOVABLE_RUN_ FROM_SWAP",	false },	// If the image is on removable media, fully load it and copy it to the swap file.
{ 0x0800, "IMAGE_FILE_NET_RUN_FROM_SWAP",			false },	// If the image is on network media, fully load it and copy it to the swap file.
{ 0x1000, "IMAGE_FILE_SYSTEM",						false },	// The image file is a system file, not a user program.
{ 0x2000, "IMAGE_FILE_DLL",							false },	// The image file is a dynamic - link library(DLL).Such files are considered executable files for almost all purposes, although they cannot be directly run.
{ 0x8000, "IMAGE_FILE_BYTES_REVERSED_HI",			false },	// Big endian : the MSB precedes the LSB in memory.This flag is deprecated and should be zero.
{ 0x4000, "IMAGE_FILE_UP_SYSTEM_ONLY",				false },	// The file should be run only on a uniprocessor machine.
};

typedef struct _DLL_CHARACTERISTICS
{
	int value;
	const char *flagName;
	bool isActive;
} DLL_CHARACTERISTICS;

DLL_CHARACTERISTICS dll_characteristics[NUMBER_OF_DLL_CHARACTERISTICS] = {
{ 0x0001, "", false }, // Reserved, must be zero.
{ 0x0002, "", false }, // Reserved, must be zero.
{ 0x0004, "", false }, // Reserved, must be zero.
{ 0x0008, "", false }, // Reserved, must be zero.
{ 0x0020, "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA", false }, // Image can handle a high entropy 64 - bit virtual address space.	
{ 0x0040, "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE", false }, // DLL can be relocated at load time.	
{ 0x0080, "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY", false }, // Code Integrity checks are enforced.	
{ 0x0100, "IMAGE_DLLCHARACTERISTICS_NX_COMPAT", false }, // Image is NX compatible. 
{ 0x0200, "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION", false }, // Isolation aware, but do not isolate the image.
{ 0x0400, "IMAGE_DLLCHARACTERISTICS_NO_SEH", false }, // Does not use structured exception(SE) handling.No SE handler may be called in this image.
{ 0x0800, "IMAGE_DLLCHARACTERISTICS_NO_BIND", false }, // Do not bind the image.
{ 0x1000, "IMAGE_DLLCHARACTERISTICS_APPCONTAINER", false }, // Image must execute in an AppContainer.
{ 0x2000, "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER", false }, // A WDM driver.
{ 0x4000, "IMAGE_DLLCHARACTERISTICS_GUARD_CF", false }, // Image supports Control Flow Guard.
{ 0x8000, "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE", false }, // Terminal Server aware.
};

typedef struct _SECTION_CHARACTERISTICS
{
	int value;
	const char *flagName;
	bool isActive;
} SECTION_CHARACTERISTICS;

SECTION_CHARACTERISTICS section_characteristics[NUMBER_OF_SECTION_CHARACTERISTICS] = {
{ 0x00000000, "", false }, // Reserved for future use.
{ 0x00000001, "", false }, // Reserved for future use.
{ 0x00000002, "", false }, // Reserved for future use.
{ 0x00000004, "", false }, // Reserved for future use.
{ 0x00000008, "IMAGE_SCN_TYPE_NO_PAD", false }, // The section should not be padded to the next boundary.This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES.This is valid only for object files.
{ 0x00000010, "", false }, // Reserved for future use.
{ 0x00000020, "IMAGE_SCN_CNT_CODE", false }, // The section contains executable code
{ 0x00000040, "IMAGE_SCN_CNT_INITIALIZED_DATA", false }, // The section contains initialized data.
{ 0x00000080, "IMAGE_SCN_CNT_UNINITIALIZED_DATA", false }, // The section contains uninitialized data.
{ 0x00000100, "IMAGE_SCN_LNK_OTHER", false }, // Reserved for future use.
{ 0x00000200, "IMAGE_SCN_LNK_INFO", false }, // The section contains comments or other information.The.drectve section has this type.This is valid for object files only.
{ 0x00000400, "", false }, // Reserved for future use.
{ 0x00000800, "IMAGE_SCN_LNK_REMOVE", false }, // The section will not become part of the image.This is valid only for object files.
{ 0x00001000, "IMAGE_SCN_LNK_COMDAT", false }, // The section contains COMDAT data.For more information, see COMDAT Sections(Object Only).This is valid only for object files.
{ 0x00008000, "IMAGE_SCN_GPREL", false }, // The section contains data referenced through the global pointer(GP).
{ 0x00020000, "IMAGE_SCN_MEM_PURGEABLE", false }, // Reserved for future use.
{ 0x00020000, "IMAGE_SCN_MEM_16BIT", false }, // Reserved for future use.
{ 0x00040000, "IMAGE_SCN_MEM_LOCKED", false }, // Reserved for future use.
{ 0x00080000, "IMAGE_SCN_MEM_PRELOAD", false }, // Reserved for future use.
{ 0x00100000, "IMAGE_SCN_ALIGN_1BYTES", false }, // Align data on a 1 - byte boundary.Valid only for object files.    
{ 0x00200000, "IMAGE_SCN_ALIGN_2BYTES", false }, // Align data on a 2 - byte boundary.Valid only for object files.    
{ 0x00300000, "IMAGE_SCN_ALIGN_4BYTES", false }, // Align data on a 4 - byte boundary.Valid only for object files.    
{ 0x00400000, "IMAGE_SCN_ALIGN_8BYTES", false }, // Align data on an 8 - byte boundary.Valid only for object files.   
{ 0x00500000, "IMAGE_SCN_ALIGN_16BYTES", false }, // Align data on a 16 - byte boundary.Valid only for object files.   
{ 0x00600000, "IMAGE_SCN_ALIGN_32BYTES", false }, // Align data on a 32 - byte boundary.Valid only for object files.   
{ 0x00700000, "IMAGE_SCN_ALIGN_64BYTES", false }, // Align data on a 64 - byte boundary.Valid only for object files.   
{ 0x00800000, "IMAGE_SCN_ALIGN_128BYTES", false }, // Align data on a 128 - byte boundary.Valid only for object files.  
{ 0x00900000, "IMAGE_SCN_ALIGN_256BYTES", false }, // Align data on a 256 - byte boundary.Valid only for object files.  
{ 0x00A00000, "IMAGE_SCN_ALIGN_512BYTES", false }, // Align data on a 512 - byte boundary.Valid only for object files.  
{ 0x00B00000, "IMAGE_SCN_ALIGN_1024BYTES", false }, // Align data on a 1024 - byte boundary.Valid only for object files. 
{ 0x00C00000, "IMAGE_SCN_ALIGN_2048BYTES", false }, // Align data on a 2048 - byte boundary.Valid only for object files. 
{ 0x00D00000, "IMAGE_SCN_ALIGN_4096BYTES", false }, // Align data on a 4096 - byte boundary.Valid only for object files. 
{ 0x00E00000, "IMAGE_SCN_ALIGN_8192BYTES", false }, // Align data on an 8192 - byte boundary.Valid only for object files.
{ 0x01000000, "IMAGE_SCN_LNK_NRELOC_OVFL", false }, // The section contains extended relocations.
{ 0x02000000, "IMAGE_SCN_MEM_DISCARDABLE", false }, // The section can be discarded as needed.
{ 0x04000000, "IMAGE_SCN_MEM_NOT_CACHED", false }, // The section cannot be cached.
{ 0x08000000, "IMAGE_SCN_MEM_NOT_PAGED", false }, // The section is not pageable.
{ 0x10000000, "IMAGE_SCN_MEM_SHARED", false }, // The section can be shared in memory.
{ 0x20000000, "IMAGE_SCN_MEM_EXECUTE", false }, // The section can be executed as code.
{ 0x40000000, "IMAGE_SCN_MEM_READ", false }, // The section can be read.
{ 0x80000000, "IMAGE_SCN_MEM_WRITE", false }, // The section can be written to.
};

typedef struct _IDD_DIR_NAMES
{
	int id;
	const char *fieldName;
} IDD_DIR_NAMES;

IDD_DIR_NAMES idd_names[NUMBER_OF_DATA_DIRECTORY_ENTRIES] = {
	{ 0x00, "Export Table" },
	{ 0x01, "Import Table" },
	{ 0x02, "Resource Table" },
	{ 0x03, "Exception Table" },
	{ 0x04, "Certificate Table" },
	{ 0x05, "Base Relocation Table" },
	{ 0x06, "Debug" },
	{ 0x07, "Architecture" },
	{ 0x08, "Global Ptr" },
	{ 0x09, "TLS Table" },
	{ 0x0a, "Load Config Table" },
	{ 0x0b, "Bount Import" },
	{ 0x0c, "IAT" },
	{ 0x0d, "Delay Import Descriptor" },
	{ 0x0e, "CLR Runtime Header" },
	{ 0x0f, "Reserved" },
};



typedef struct _IMAGE_DOS_HEADER_EXT
{
	unsigned long offset;
	const char *fieldName;
	void **fieldValue;
	int size;
} IDS;

IDS ids[7] = {
	{ 0, "Machine", 0x00, 2},
	{ 2, "NumberOfSections", 0x00, 2},
	{ 4, "TimeDateStamp", 0x00, 4},
	{ 8, "PointerToSymbolTable", 0x00, 4},
	{ 12, "NumberOfSymbols", 0x00,4},
	{ 16, "SizeOfOptionalHeader", 0x00, 2},
	{ 18, "Characteristics", 0x00, 2},
};
