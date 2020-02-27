#pragma once
#include <stdio.h>
#include <windows.h>
#include <winnt.h>
#define MAX_STRING_SIZE 0x100
ULONGLONG convertToUlonglong(UINT8 *buffer)
{
	ULONGLONG res = 0;
	res += ( ULONGLONG )buffer[0];
	res += ( ULONGLONG )buffer[1] << 8;
	res += ( ULONGLONG )buffer[2] << 16;
	res += ( ULONGLONG )buffer[3] << 24;
	res += ( ULONGLONG )buffer[4] << 32;
	res += ( ULONGLONG )buffer[5] << 40;
	res += ( ULONGLONG )buffer[6] << 48;
	res += ( ULONGLONG )buffer[7] << 56;

	return res;
}

DWORD convertToDword(UINT8 *buffer)
{
	DWORD res = 0;
	res += buffer[0];
	res += buffer[1] << 8;
	res += buffer[2] << 16;
	res += buffer[3] << 24;

	return res;
}

WORD convertToWord(UINT8 *buffer)
{
	WORD res = 0;
	res += buffer[0];
	res += buffer[1] << 8;

	return res;
}

DWORD ceiling(DWORD number, DWORD unit)
{
	DWORD remainder = number % unit;
	DWORD quotient = number / unit;

	if (remainder < unit)
	{
		return (quotient + 1) * unit;
	}

	else 
	{
		return number;
	}
}

DWORD addDwordToLpvoid(LPVOID base, DWORD adjustment)
{
	// bound check 
	return (DWORD)base + adjustment;
}

char *getStringFromBuffer(DWORD offset)
{
	char szTempBuffer[MAX_STRING_SIZE] = { 0x00, };
	char *szDllName = NULL;
	DWORD dwStrLen = 0;

	strncpy_s(szTempBuffer, (const char *)offset, MAX_STRING_SIZE);
	dwStrLen = strnlen_s(szTempBuffer, MAX_STRING_SIZE);
	if (dwStrLen > MAX_STRING_SIZE)
	{
		printf("invalid dwStrLen\n");
		exit(-1);
	}

	szDllName = (char *)malloc(dwStrLen * sizeof(char) + 2);
	if (!szDllName)
	{
		printf("failed to allocate szDllName\n");
		exit(-1);
	}

	memcpy(szDllName, szTempBuffer, dwStrLen);
	memset(szDllName + dwStrLen, 0x00, 2);

	return szDllName;
}

VOID printBigLine()
{
	printf("=============================================\n");
}

VOID printSmallLine()
{
	printf("- - - - - - - - - - - - - - - - - - - - - - -\n");
}

VOID printDosHeader(IMAGE_DOS_HEADER *dosHeader, DWORD baseOffset)
{
	// printf("%016I64x, %x", (void **)dosHeader, dosHeader->e_magic);
	printBigLine();
	printf("IMAGE_DOS_HEADER (TODO)\n");
	printBigLine();

}

VOID printFileHeader(IMAGE_FILE_HEADER *ifh)
{
	printBigLine();
	printf("IMAGE_FILE_HEADER\n");
	printBigLine();

	printf("%-36s %04x\n", "Machine", ifh->Machine);
	printf("%-36s %04x\n", "NumberOfSections", ifh->NumberOfSections);
	printf("%-36s %08x\n", "TimeDateStamp", ifh->TimeDateStamp);				// TODO convert into actual time.
	printf("%-36s %08x\n", "PointerToSymbolTable", ifh->PointerToSymbolTable);
	printf("%-36s %08x\n", "NumberOfSymbols", ifh->NumberOfSymbols);
	printf("%-36s %04x\n", "SizeOfOptionalHeader", ifh->SizeOfOptionalHeader);
	printf("%-36s %04x\n", "Characteristics", ifh->Characteristics);
	printSmallLine();

	int count = 0;

	for (int i = 0; i < NUMBER_OF_IFH_CHARACTERISTICS; i++)
	{
		if (ifh->Characteristics & ifh_characteristics[i].value)
		{
			ifh_characteristics[i].isActive = true;
			count++;
		}
	}

	if (count == 0)
	{
		printf("Invalid Characteristics value in IMAGE_FILE_HEADER");
		exit(-1);
	}

	for (int i = 0; i < NUMBER_OF_IFH_CHARACTERISTICS; i++)
	{
		if (ifh_characteristics[i].isActive)
		{
			printf("%s\n", ifh_characteristics[i].flagName);
		}
	}

}

VOID printOptionalHeader32(IMAGE_OPTIONAL_HEADER32 *ioh32)
{
	printBigLine();
	printf("IMAGE_OPTIONAL_HEADER32\n");
	printBigLine();

	printf("%-36s %08x\n", "Magic", ioh32->Magic);
	printf("%-36s %04x\n", "MajorLinkerVersion", ioh32->MajorLinkerVersion);
	printf("%-36s %04x\n", "MinorLinkerVersion", ioh32->MinorLinkerVersion);
	printf("%-36s %08x\n", "SizeOfCode", ioh32->SizeOfCode);
	printf("%-36s %08x\n", "SizeOfInitializedData", ioh32->SizeOfInitializedData);
	printf("%-36s %08x\n", "SizeOfUninitializedData", ioh32->SizeOfUninitializedData);
	printf("%-36s %08x\n", "AddressOfEntryPoint", ioh32->AddressOfEntryPoint);
	printf("%-36s %08x\n", "BaseOfCode", ioh32->BaseOfCode);
	printf("%-36s %08x\n", "ImageBase", ioh32->ImageBase);
	printf("%-36s %08x\n", "SectionAlignment", ioh32->SectionAlignment);
	printf("%-36s %08x\n", "FileAlignment", ioh32->FileAlignment);
	printf("%-36s %04x\n", "MajorOperatingSystemVersion", ioh32->MajorOperatingSystemVersion);
	printf("%-36s %04x\n", "MinorOperatingSystemVersion", ioh32->MinorOperatingSystemVersion);
	printf("%-36s %04x\n", "MajorImageVersion", ioh32->MajorImageVersion);
	printf("%-36s %04x\n", "MinorImageVersion", ioh32->MinorImageVersion);
	printf("%-36s %04x\n", "MajorSubsystemVersion", ioh32->MajorSubsystemVersion);
	printf("%-36s %04x\n", "MinorSubsystemVersion", ioh32->MinorSubsystemVersion);
	printf("%-36s %08x\n", "Win32VersionValue", ioh32->Win32VersionValue);
	printf("%-36s %08x\n", "SizeOfImage", ioh32->SizeOfImage);
	printf("%-36s %08x\n", "SizeOfHeaders", ioh32->SizeOfHeaders);
	printf("%-36s %08x\n", "CheckSum", ioh32->CheckSum);
	printf("%-36s %04x\n", "Subsystem", ioh32->Subsystem);
	printf("%-36s %04x\n", "DllCharacteristics", ioh32->DllCharacteristics);
	printf("%-36s %08x\n", "SizeOfStackReserve", ioh32->SizeOfStackReserve);
	printf("%-36s %08x\n", "SizeOfStackCommit", ioh32->SizeOfStackCommit);
	printf("%-36s %08x\n", "SizeOfHeapReserve", ioh32->SizeOfHeapReserve);
	printf("%-36s %08x\n", "SizeOfHeapCommit", ioh32->SizeOfHeapCommit);
	printf("%-36s %08x\n", "LoaderFlags", ioh32->LoaderFlags);
	printf("%-36s %08x\n", "NumberOfRvaAndSizes", ioh32->NumberOfRvaAndSizes);
	printSmallLine();

	for (DWORD i = 0; i < ioh32->NumberOfRvaAndSizes; i++)
	{
		printf("%-25s ", idd_names[i].fieldName);
		printf("%08X | ", ioh32->DataDirectory[i].VirtualAddress);
		printf("%08X\n", ioh32->DataDirectory[i].Size);
	}
}

VOID printOptionalHeader64(IMAGE_OPTIONAL_HEADER64 *ioh64)
{
	printBigLine();
	printf("IMAGE_OPTIONAL_HEADER64\n");
	printBigLine();

	printf("%-36s %08x\n", "Magic", ioh64->Magic);
	printf("%-36s %04x\n", "MajorLinkerVersion", ioh64->MajorLinkerVersion);
	printf("%-36s %04x\n", "MinorLinkerVersion", ioh64->MinorLinkerVersion);
	printf("%-36s %08x\n", "SizeOfCode", ioh64->SizeOfCode);
	printf("%-36s %08x\n", "SizeOfInitializedData", ioh64->SizeOfInitializedData);
	printf("%-36s %08x\n", "SizeOfUninitializedData", ioh64->SizeOfUninitializedData);
	printf("%-36s %08x\n", "AddressOfEntryPoint", ioh64->AddressOfEntryPoint);
	printf("%-36s %08x\n", "BaseOfCode", ioh64->BaseOfCode);
	printf("%-36s %016I64x\n", "ImageBase", ioh64->ImageBase);
	printf("%-36s %08x\n", "SectionAlignment", ioh64->SectionAlignment);
	printf("%-36s %08x\n", "FileAlignment", ioh64->FileAlignment);
	printf("%-36s %04x\n", "MajorOperatingSystemVersion", ioh64->MajorOperatingSystemVersion);
	printf("%-36s %04x\n", "MinorOperatingSystemVersion", ioh64->MinorOperatingSystemVersion);
	printf("%-36s %04x\n", "MajorImageVersion", ioh64->MajorImageVersion);
	printf("%-36s %04x\n", "MinorImageVersion", ioh64->MinorImageVersion);
	printf("%-36s %04x\n", "MajorSubsystemVersion", ioh64->MajorSubsystemVersion);
	printf("%-36s %04x\n", "MinorSubsystemVersion", ioh64->MinorSubsystemVersion);
	printf("%-36s %08x\n", "Win32VersionValue", ioh64->Win32VersionValue);
	printf("%-36s %08x\n", "SizeOfImage", ioh64->SizeOfImage);
	printf("%-36s %08x\n", "SizeOfHeaders", ioh64->SizeOfHeaders);
	printf("%-36s %08x\n", "CheckSum", ioh64->CheckSum);
	printf("%-36s %04x\n", "Subsystem", ioh64->Subsystem);
	printf("%-36s %04x\n", "DllCharacteristics", ioh64->DllCharacteristics);
	printf("%-36s %016I64x\n", "SizeOfStackReserve", ioh64->SizeOfStackReserve);
	printf("%-36s %016I64x\n", "SizeOfStackCommit", ioh64->SizeOfStackCommit);
	printf("%-36s %016I64x\n", "SizeOfHeapReserve", ioh64->SizeOfHeapReserve);
	printf("%-36s %016I64x\n", "SizeOfHeapCommit", ioh64->SizeOfHeapCommit);
	printf("%-36s %08x\n", "LoaderFlags", ioh64->LoaderFlags);
	printf("%-36s %08x\n", "NumberOfRvaAndSizes", ioh64->NumberOfRvaAndSizes);
	printSmallLine();

	for (DWORD i = 0; i < ioh64->NumberOfRvaAndSizes; i++)
	{
		printf("%-25s ", idd_names[i].fieldName);
		printf("%08X | ", ioh64->DataDirectory[i].VirtualAddress);
		printf("%08X\n", ioh64->DataDirectory[i].Size);
	}
}


VOID printSectionHeader(IMAGE_SECTION_HEADER *sectionHeader, DWORD sectionNo)
{
	printBigLine();
	printf("IMAGE_SECTION_HEADER [%d]\n", sectionNo);
	printBigLine();

	printf("%-36s %s\n", "Name", sectionHeader->Name);
	printf("%-36s %08x\n", "VirtualSize", sectionHeader->Misc.VirtualSize);
	printf("%-36s %08x\n", "VirtualAddress", sectionHeader->VirtualAddress);
	printf("%-36s %08x\n", "SizeOfRawData", sectionHeader->SizeOfRawData);
	printf("%-36s %08x\n", "PointerToRawData", sectionHeader->PointerToRawData);
	printf("%-36s %08x\n", "PointerToRelocations", sectionHeader->PointerToRelocations);
	printf("%-36s %08x\n", "PointerToLinenumbers", sectionHeader->PointerToLinenumbers);
	printf("%-36s %04x\n", "NumberOfRelocations", sectionHeader->NumberOfRelocations);
	printf("%-36s %04x\n", "PointerToLinenumbers", sectionHeader->PointerToLinenumbers);
	printf("%-36s %08x\n", "Characteristics", sectionHeader->Characteristics);
	printSmallLine();

	int count = 0;

	for (int i = 0; i < NUMBER_OF_SECTION_CHARACTERISTICS; i++)
	{
		if (sectionHeader->Characteristics & section_characteristics[i].value)
		{
			section_characteristics[i].isActive = true;
			count++;
		}
	}
	if (count == 0)
	{
		printf("Invalid Characteristics value in IMAGE_SECTION_HEADER");
		exit(-1);
	}

	for (int i = 0; i < NUMBER_OF_SECTION_CHARACTERISTICS; i++)
	{
		if (section_characteristics[i].isActive)
		{
			printf("%s\n", section_characteristics[i].flagName);
			section_characteristics[i].isActive = false; // after printing, revert it back to false, maybe I should use an array and keep information of each section 
		}
	}

}

DWORD parseImageOptionalHeader32(IMAGE_OPTIONAL_HEADER32 *ioh32, UINT8 *lpBuffer, DWORD dwCursor, DWORD sizeOfOptionalHeader)
{
	DWORD offsetToIOH = dwCursor;
	ioh32->Magic = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);
	ioh32->MajorLinkerVersion = lpBuffer[dwCursor++];
	ioh32->MinorLinkerVersion = lpBuffer[dwCursor++];
	ioh32->SizeOfCode = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh32->SizeOfInitializedData = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh32->SizeOfUninitializedData = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh32->AddressOfEntryPoint = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh32->BaseOfCode = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh32->BaseOfData = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh32->ImageBase = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh32->SectionAlignment = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh32->FileAlignment = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh32->MajorOperatingSystemVersion = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);
	ioh32->MinorOperatingSystemVersion = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);
	ioh32->MajorImageVersion = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);
	ioh32->MinorImageVersion = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);
	ioh32->MajorSubsystemVersion = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);
	ioh32->MinorSubsystemVersion = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);
	ioh32->Win32VersionValue = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh32->SizeOfImage = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh32->SizeOfHeaders = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh32->CheckSum = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh32->Subsystem = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);
	ioh32->DllCharacteristics = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);
	ioh32->SizeOfStackReserve = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh32->SizeOfStackCommit = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh32->SizeOfHeapReserve = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh32->SizeOfHeapCommit = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh32->LoaderFlags = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh32->NumberOfRvaAndSizes = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);

	for (DWORD i = 0; i < ioh32->NumberOfRvaAndSizes && dwCursor - offsetToIOH < sizeOfOptionalHeader; i++)
	{
		ioh32->DataDirectory[i].VirtualAddress = convertToDword(lpBuffer + dwCursor);
		dwCursor += sizeof(DWORD);
		ioh32->DataDirectory[i].Size = convertToDword(lpBuffer + dwCursor);
		dwCursor += sizeof(DWORD);
	}
	return dwCursor;
}

DWORD parseImageOptionalHeader64(IMAGE_OPTIONAL_HEADER64 *ioh64, UINT8 *lpBuffer, DWORD dwCursor, DWORD sizeOfOptionalHeader)
{
	DWORD offsetToIOH = dwCursor;
	ioh64->Magic = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);
	ioh64->MajorLinkerVersion = lpBuffer[dwCursor++];
	ioh64->MinorLinkerVersion = lpBuffer[dwCursor++];
	ioh64->SizeOfCode = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh64->SizeOfInitializedData = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh64->SizeOfUninitializedData = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh64->AddressOfEntryPoint = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh64->BaseOfCode = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh64->ImageBase = convertToUlonglong(lpBuffer + dwCursor);
	dwCursor += sizeof(ULONGLONG);
	ioh64->SectionAlignment = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh64->FileAlignment = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh64->MajorOperatingSystemVersion = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);
	ioh64->MinorOperatingSystemVersion = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);
	ioh64->MajorImageVersion = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);
	ioh64->MinorImageVersion = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);
	ioh64->MajorSubsystemVersion = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);
	ioh64->MinorSubsystemVersion = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);
	ioh64->Win32VersionValue = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh64->SizeOfImage = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh64->SizeOfHeaders = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh64->CheckSum = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh64->Subsystem = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);
	ioh64->DllCharacteristics = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);
	ioh64->SizeOfStackReserve = convertToUlonglong(lpBuffer + dwCursor);
	dwCursor += sizeof(ULONGLONG);
	ioh64->SizeOfStackCommit = convertToUlonglong(lpBuffer + dwCursor);
	dwCursor += sizeof(ULONGLONG);
	ioh64->SizeOfHeapReserve = convertToUlonglong(lpBuffer + dwCursor);
	dwCursor += sizeof(ULONGLONG);
	ioh64->SizeOfHeapCommit = convertToUlonglong(lpBuffer + dwCursor);
	dwCursor += sizeof(ULONGLONG);
	ioh64->LoaderFlags = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	ioh64->NumberOfRvaAndSizes = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);

	for (DWORD i = 0; i < ioh64->NumberOfRvaAndSizes && dwCursor - offsetToIOH < sizeOfOptionalHeader; i++)
	{
		ioh64->DataDirectory[i].VirtualAddress = convertToDword(lpBuffer + dwCursor);
		dwCursor += sizeof(DWORD);
		ioh64->DataDirectory[i].Size = convertToDword(lpBuffer + dwCursor);
		dwCursor += sizeof(DWORD);
	}
	return dwCursor;
}

DWORD parseDosHeader(IMAGE_DOS_HEADER *dosHeader, UINT8 *lpBuffer, DWORD dwCursor)
{
	dosHeader->e_magic = convertToWord(lpBuffer);
	if (dosHeader->e_magic != 0x5a4d)
	{
		printf("MZ signature not found");
		exit(-1);
	}

	dwCursor += sizeof(WORD);

	dosHeader->e_cblp = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);

	dosHeader->e_cp = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);

	dosHeader->e_crlc = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);

	dosHeader->e_cparhdr = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);

	dosHeader->e_minalloc = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);

	dosHeader->e_maxalloc = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);

	dosHeader->e_ss = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);

	dosHeader->e_sp = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);

	dosHeader->e_csum = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);

	dosHeader->e_ip = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);

	dosHeader->e_cs = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);

	dosHeader->e_lfarlc = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);

	dosHeader->e_ovno = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);

	// dosHeader->e_res[4];	
	dwCursor += sizeof(WORD) * 4;

	// dosHeader->e_oemid;
	dwCursor += sizeof(WORD);

	// dosHeader->e_oeminfo;
	dwCursor += sizeof(WORD);

	// dosHeader->e_res2[10];
	dwCursor += sizeof(WORD) * 10;

	dosHeader->e_lfanew = convertToDword(lpBuffer + dwCursor);

	return dwCursor;
}

DWORD parseImageFileHeader(IMAGE_FILE_HEADER *ifh, UINT8 *lpBuffer, DWORD dwCursor)
{
	DWORD ntSignature = convertToDword(lpBuffer + dwCursor);
	if (ntSignature != 0x4550)
	{
		printf("PE signature not found");
		exit(-1);
	}

	dwCursor += sizeof(DWORD);

	ifh->Machine = convertToWord(lpBuffer + dwCursor);
	ids[0].fieldValue = (void **)ifh->Machine;
	dwCursor += sizeof(WORD);

	bool typecheck = false;

	for (int i = 0; i < NUMBER_OF_MACHINE_TYPES; i++)
	{
		if (ifh->Machine == ifh_machines[i])
		{
			typecheck = true;
			break;
		}
	}

	if (!typecheck)
	{
		printf("Invalid Machine value in IMAGE_FILE_HEADER");
		exit(-1);
	}

	ifh->NumberOfSections = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);

	ifh->TimeDateStamp = convertToDword(lpBuffer + dwCursor);
	// [TODO] add conversion to realtime
	dwCursor += sizeof(DWORD);

	// The file offset of the COFF symbol table, or zero if no COFF symbol table is present. 
	// This value should be zero for an image because COFF debugging information is deprecated.
	ifh->PointerToSymbolTable = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);

	//The number of entries in the symbol table. This data can be used to locate the string table, which immediately follows the symbol table. 
	// This value should be zero for an image because COFF debugging information is deprecated.
	ifh->NumberOfSymbols = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);

	// The size of the optional header, which is required for executable files but not for object files. This value should be zero for an object file. 
	// usual size x86: 0xE0, x64: 0xF0
	ifh->SizeOfOptionalHeader = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);

	ifh->Characteristics = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);

	return dwCursor;
}

DWORD parseSectionHeader(IMAGE_SECTION_HEADER *sectionHeader, UINT8 *lpBuffer, DWORD dwCursor, DWORD sectionNo)
{
	memcpy(sectionHeader->Name, lpBuffer + dwCursor, IMAGE_SIZEOF_SHORT_NAME);
	dwCursor += IMAGE_SIZEOF_SHORT_NAME;
	sectionHeader->Misc.VirtualSize = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	sectionHeader->VirtualAddress = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	sectionHeader->SizeOfRawData = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	sectionHeader->PointerToRawData = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	sectionHeader->PointerToRelocations = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	sectionHeader->PointerToLinenumbers = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);
	sectionHeader->NumberOfRelocations = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);
	sectionHeader->NumberOfLinenumbers = convertToWord(lpBuffer + dwCursor);
	dwCursor += sizeof(WORD);
	sectionHeader->Characteristics = convertToDword(lpBuffer + dwCursor);
	dwCursor += sizeof(DWORD);

	return dwCursor;
}
