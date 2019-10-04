#pragma once
// Machine Types
// The Machine field has one of the following values that specifies its CPU type.An image file can be run only on the specified machine or on a system that emulates the specified machine.

// Constant	Value	Description
#define NUMBER_OF_MACHINE_TYPES 25
#define NUMBER_OF_CHARACTERISTICS 15


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
} IFH_CHARACTERISTICS ;

IFH_CHARACTERISTICS ihfc[NUMBER_OF_CHARACTERISTICS] = {
{ 0x0001, "IMAGE_FILE_RELOCS_STRIPPED", false }, 			// Image only, Windows CE, and Microsoft Windows NT and later.This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address.If the base address is not available, the loader reports an error.The default behavior of the linker is to strip base relocations from executable(EXE) files.
{ 0x0002, "IMAGE_FILE_EXECUTABLE_IMAGE", false }, 		// 	Image only.This indicates that the image file is valid and can be run.If this flag is not set, it indicates a linker error.
{ 0x0004, "IMAGE_FILE_LINE_NUMS_STRIPPED", false }, 		// COFF line numbers have been removed.This flag is deprecated and should be zero.
{ 0x0008, "IMAGE_FILE_LOCAL_SYMS_STRIPPED", false }, 		// COFF symbol table entries for local symbols have been removed.This flag is deprecated and should be zero.
{ 0x0010, "IMAGE_FILE_AGGRESSIVE_WS_TRIM", false }, 		// Obsolete.Aggressively trim working set.This flag is deprecated for Windows 2000 and later and must be zero.
{ 0x0020, "IMAGE_FILE_LARGE_ADDRESS_ AWARE", false }, 	// 	Application can handle > 2 - GB addresses.	0x0040	This flag is reserved for future use.
{ 0x0080, "IMAGE_FILE_BYTES_REVERSED_LO", false }, 		// 	Little endian : the least significant bit(LSB) precedes the most significant bit(MSB) in memory.This flag is deprecated and should be zero.
{ 0x0100, "IMAGE_FILE_32BIT_MACHINE", false }, 			// 	Machine is based on a 32 - bit - word architecture.
{ 0x0200, "IMAGE_FILE_DEBUG_STRIPPED", false }, 			// Debugging information is removed from the image file.
{ 0x0400, "IMAGE_FILE_REMOVABLE_RUN_ FROM_SWAP", false }, // 	If the image is on removable media, fully load it and copy it to the swap file.
{ 0x0800, "IMAGE_FILE_NET_RUN_FROM_SWAP", false }, 		// 	If the image is on network media, fully load it and copy it to the swap file.
{ 0x1000, "IMAGE_FILE_SYSTEM", false }, 					// The image file is a system file, not a user program.
{ 0x2000, "IMAGE_FILE_DLL", false }, 						// The image file is a dynamic - link library(DLL).Such files are considered executable files for almost all purposes, although they cannot be directly run.
{ 0x8000, "IMAGE_FILE_BYTES_REVERSED_HI", false }, 		// 	Big endian : the MSB precedes the LSB in memory.This flag is deprecated and should be zero.
{ 0x4000, "IMAGE_FILE_UP_SYSTEM_ONLY", false }, 			// The file should be run only on a uniprocessor machine.
};
