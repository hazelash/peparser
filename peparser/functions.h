#pragma once
#include <stdio.h>
#include <windows.h>
#include <winnt.h>

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

VOID printIOH32(IMAGE_OPTIONAL_HEADER32 *ioh32)
{
	printf("Magic %08x\n", ioh32->Magic);
	printf("MajorLinkerVersion %08x\n", ioh32->MajorLinkerVersion);
	printf("MinorLinkerVersion %08x\n", ioh32->MinorLinkerVersion);
	printf("SizeOfCode %08x\n", ioh32->SizeOfCode);
	printf("SizeOfInitializedData %08x\n", ioh32->SizeOfInitializedData);
	printf("SizeOfUninitializedData %08x\n", ioh32->SizeOfUninitializedData);
	printf("AddressOfEntryPoint %08x\n", ioh32->AddressOfEntryPoint);
	printf("BaseOfCode %08x\n", ioh32->BaseOfCode);
	printf("BaseOfData %08x\n", ioh32->BaseOfData);
	printf("ImageBase %08x\n", ioh32->ImageBase);
	printf("SectionAlignment %08x\n", ioh32->SectionAlignment);
	printf("FileAlignment %08x\n", ioh32->FileAlignment);
	printf("MajorOperatingSystemVersion %08x\n", ioh32->MajorOperatingSystemVersion);
	printf("MinorOperatingSystemVersion %08x\n", ioh32->MinorOperatingSystemVersion);
	printf("MajorImageVersion %08x\n", ioh32->MajorImageVersion);
	printf("MinorImageVersion %08x\n", ioh32->MinorImageVersion);
	printf("MajorSubsystemVersion %08x\n", ioh32->MajorSubsystemVersion);
	printf("MinorSubsystemVersion %08x\n", ioh32->MinorSubsystemVersion);
	printf("Win32VersionValue %08x\n", ioh32->Win32VersionValue);
	printf("SizeOfImage %08x\n", ioh32->SizeOfImage);
	printf("SizeOfHeaders %08x\n", ioh32->SizeOfHeaders);
	printf("CheckSum %08x\n", ioh32->CheckSum);
	printf("Subsystem %08x\n", ioh32->Subsystem);
	printf("DllCharacteristics %08x\n", ioh32->DllCharacteristics);
	printf("SizeOfStackReserve %08x\n", ioh32->SizeOfStackReserve);
	printf("SizeOfStackCommit %08x\n", ioh32->SizeOfStackCommit);
	printf("SizeOfHeapReserve %08x\n", ioh32->SizeOfHeapReserve);
	printf("SizeOfHeapCommit %08x\n", ioh32->SizeOfHeapCommit);
	printf("LoaderFlags %08x\n", ioh32->LoaderFlags);
	printf("NumberOfRvaAndSizes %08x\n", ioh32->NumberOfRvaAndSizes);

	for (DWORD i = 0; i < ioh32->NumberOfRvaAndSizes; i++)
	{
		printf("%08X | ", ioh32->DataDirectory[i].VirtualAddress);
		printf("%08X\n", ioh32->DataDirectory[i].Size);
	}
}

VOID printDosHeader(IMAGE_DOS_HEADER *dosHeader, DWORD baseOffset)
{
	// printf("%016I64x, %x", (void **)dosHeader, dosHeader->e_magic);
	printf("TODO\n");
}

VOID printIOH64(IMAGE_OPTIONAL_HEADER64 *ioh64)
{
	printf("Magic	%08x\n", ioh64->Magic);
	printf("MajorLinkerVersion	%08x\n", ioh64->MajorLinkerVersion);
	printf("MinorLinkerVersion	%08x\n", ioh64->MinorLinkerVersion);
	printf("SizeOfCode	%08x\n", ioh64->SizeOfCode);
	printf("SizeOfInitializedData	%08x\n", ioh64->SizeOfInitializedData);
	printf("SizeOfUninitializedData	%08x\n", ioh64->SizeOfUninitializedData);
	printf("AddressOfEntryPoint	%08x\n", ioh64->AddressOfEntryPoint);
	printf("BaseOfCode	%08x\n", ioh64->BaseOfCode);
	printf("ImageBase	%016I64x\n", ioh64->ImageBase);
	printf("SectionAlignment	%08x\n", ioh64->SectionAlignment);
	printf("FileAlignment	%08x\n", ioh64->FileAlignment);
	printf("MajorOperatingSystemVersion	%08x\n", ioh64->MajorOperatingSystemVersion);
	printf("MinorOperatingSystemVersion	%08x\n", ioh64->MinorOperatingSystemVersion);
	printf("MajorImageVersion	%08x\n", ioh64->MajorImageVersion);
	printf("MinorImageVersion	%08x\n", ioh64->MinorImageVersion);
	printf("MajorSubsystemVersion	%08x\n", ioh64->MajorSubsystemVersion);
	printf("MinorSubsystemVersion	%08x\n", ioh64->MinorSubsystemVersion);
	printf("Win32VersionValue	%08x\n", ioh64->Win32VersionValue);
	printf("SizeOfImage	%08x\n", ioh64->SizeOfImage);
	printf("SizeOfHeaders	%08x\n", ioh64->SizeOfHeaders);
	printf("CheckSum	%08x\n", ioh64->CheckSum);
	printf("Subsystem	%08x\n", ioh64->Subsystem);
	printf("DllCharacteristics	%08x\n", ioh64->DllCharacteristics);
	printf("SizeOfStackReserve	%016I64x\n", ioh64->SizeOfStackReserve);
	printf("SizeOfStackCommit	%016I64x\n", ioh64->SizeOfStackCommit);
	printf("SizeOfHeapReserve	%016I64x\n", ioh64->SizeOfHeapReserve);
	printf("SizeOfHeapCommit	%016I64x\n", ioh64->SizeOfHeapCommit);
	printf("LoaderFlags	%08x\n", ioh64->LoaderFlags);
	printf("NumberOfRvaAndSizes	%08x\n", ioh64->NumberOfRvaAndSizes);

	for (DWORD i = 0; i < ioh64->NumberOfRvaAndSizes; i++)
	{
		printf("%25s: ", idd_names[i].fieldName);
		printf("%08X | ", ioh64->DataDirectory[i].VirtualAddress);
		printf("%08X\n", ioh64->DataDirectory[i].Size);
	}

}

DWORD parseImageOptionalHeader32(IMAGE_OPTIONAL_HEADER32 *ioh32, UINT8 *lpBuffer, DWORD cursor, DWORD sizeOfOptionalHeader)
{
	DWORD offsetToIOH = cursor;
	ioh32->Magic = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);
	ioh32->MajorLinkerVersion = lpBuffer[cursor++];
	ioh32->MinorLinkerVersion = lpBuffer[cursor++];
	ioh32->SizeOfCode = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh32->SizeOfInitializedData = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh32->SizeOfUninitializedData = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh32->AddressOfEntryPoint = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh32->BaseOfCode = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh32->BaseOfData = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh32->ImageBase = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh32->SectionAlignment = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh32->FileAlignment = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh32->MajorOperatingSystemVersion = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);
	ioh32->MinorOperatingSystemVersion = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);
	ioh32->MajorImageVersion = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);
	ioh32->MinorImageVersion = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);
	ioh32->MajorSubsystemVersion = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);
	ioh32->MinorSubsystemVersion = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);
	ioh32->Win32VersionValue = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh32->SizeOfImage = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh32->SizeOfHeaders = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh32->CheckSum = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh32->Subsystem = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);
	ioh32->DllCharacteristics = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);
	ioh32->SizeOfStackReserve = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh32->SizeOfStackCommit = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh32->SizeOfHeapReserve = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh32->SizeOfHeapCommit = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh32->LoaderFlags = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh32->NumberOfRvaAndSizes = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);

	for (DWORD i = 0; i < ioh32->NumberOfRvaAndSizes && cursor - offsetToIOH < sizeOfOptionalHeader; i++)
	{
		ioh32->DataDirectory[i].VirtualAddress = convertToDword(lpBuffer + cursor);
		cursor += sizeof(DWORD);
		ioh32->DataDirectory[i].Size = convertToDword(lpBuffer + cursor);
		cursor += sizeof(DWORD);
	}
	return cursor;
}

DWORD parseImageOptionalHeader64(IMAGE_OPTIONAL_HEADER64 *ioh64, UINT8 *lpBuffer, DWORD cursor, DWORD sizeOfOptionalHeader)
{
	DWORD offsetToIOH = cursor;
	ioh64->Magic = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);
	ioh64->MajorLinkerVersion = lpBuffer[cursor++];
	ioh64->MinorLinkerVersion = lpBuffer[cursor++];
	ioh64->SizeOfCode = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh64->SizeOfInitializedData = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh64->SizeOfUninitializedData = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh64->AddressOfEntryPoint = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh64->BaseOfCode = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh64->ImageBase = convertToUlonglong(lpBuffer + cursor);
	cursor += sizeof(ULONGLONG);
	ioh64->SectionAlignment = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh64->FileAlignment = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh64->MajorOperatingSystemVersion = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);
	ioh64->MinorOperatingSystemVersion = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);
	ioh64->MajorImageVersion = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);
	ioh64->MinorImageVersion = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);
	ioh64->MajorSubsystemVersion = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);
	ioh64->MinorSubsystemVersion = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);
	ioh64->Win32VersionValue = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh64->SizeOfImage = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh64->SizeOfHeaders = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh64->CheckSum = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh64->Subsystem = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);
	ioh64->DllCharacteristics = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);
	ioh64->SizeOfStackReserve = convertToUlonglong(lpBuffer + cursor);
	cursor += sizeof(ULONGLONG);
	ioh64->SizeOfStackCommit = convertToUlonglong(lpBuffer + cursor);
	cursor += sizeof(ULONGLONG);
	ioh64->SizeOfHeapReserve = convertToUlonglong(lpBuffer + cursor);
	cursor += sizeof(ULONGLONG);
	ioh64->SizeOfHeapCommit = convertToUlonglong(lpBuffer + cursor);
	cursor += sizeof(ULONGLONG);
	ioh64->LoaderFlags = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	ioh64->NumberOfRvaAndSizes = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);

	for (DWORD i = 0; i < ioh64->NumberOfRvaAndSizes && cursor - offsetToIOH < sizeOfOptionalHeader; i++)
	{
		ioh64->DataDirectory[i].VirtualAddress = convertToDword(lpBuffer + cursor);
		cursor += sizeof(DWORD);
		ioh64->DataDirectory[i].Size = convertToDword(lpBuffer + cursor);
		cursor += sizeof(DWORD);
	}
	return cursor;
}

DWORD parseDosHeader(IMAGE_DOS_HEADER *dosHeader, UINT8 *lpBuffer, DWORD cursor)
{
	dosHeader->e_magic = convertToWord(lpBuffer);
	if (dosHeader->e_magic != 0x5a4d)
	{
		printf("MZ signature not found");
		exit(-1);
	}

	cursor += sizeof(WORD);

	dosHeader->e_cblp = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);

	dosHeader->e_cp = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);

	dosHeader->e_crlc = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);

	dosHeader->e_cparhdr = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);

	dosHeader->e_minalloc = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);

	dosHeader->e_maxalloc = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);

	dosHeader->e_ss = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);

	dosHeader->e_sp = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);

	dosHeader->e_csum = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);

	dosHeader->e_ip = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);

	dosHeader->e_cs = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);

	dosHeader->e_lfarlc = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);

	dosHeader->e_ovno = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);

	// dosHeader->e_res[4];	
	cursor += sizeof(WORD) * 4;

	// dosHeader->e_oemid;
	cursor += sizeof(WORD);

	// dosHeader->e_oeminfo;
	cursor += sizeof(WORD);

	// dosHeader->e_res2[10];
	cursor += sizeof(WORD) * 10;

	dosHeader->e_lfanew = convertToDword(lpBuffer + cursor);

	return cursor;
}

DWORD parseImageFileHeader(IMAGE_FILE_HEADER *ifh, UINT8 *lpBuffer, DWORD cursor)
{
	DWORD ntSignature = convertToDword(lpBuffer + cursor);
	if (ntSignature != 0x4550)
	{
		printf("PE signature not found");
		exit(-1);
	}

	cursor += sizeof(DWORD);

	ifh->Machine = convertToWord(lpBuffer + cursor);
	ids[0].fieldValue = (void **)ifh->Machine;
	cursor += sizeof(WORD);

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

	ifh->NumberOfSections = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);

	ifh->TimeDateStamp = convertToDword(lpBuffer + cursor);
	// [TODO] add conversion to realtime
	cursor += sizeof(DWORD);

	// The file offset of the COFF symbol table, or zero if no COFF symbol table is present. 
	// This value should be zero for an image because COFF debugging information is deprecated.
	ifh->PointerToSymbolTable = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);

	//The number of entries in the symbol table. This data can be used to locate the string table, which immediately follows the symbol table. 
	// This value should be zero for an image because COFF debugging information is deprecated.
	ifh->NumberOfSymbols = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);

	// The size of the optional header, which is required for executable files but not for object files. This value should be zero for an object file. 
	// usual size x86: 0xE0, x64: 0xF0
	ifh->SizeOfOptionalHeader = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);

	ifh->Characteristics = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);

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

	return cursor;
}

DWORD parseSectionHeader(IMAGE_SECTION_HEADER *sectionHeader, UINT8 *lpBuffer, DWORD cursor, DWORD sectionNo)
{
	memcpy(sectionHeader->Name, lpBuffer + cursor, IMAGE_SIZEOF_SHORT_NAME);
	cursor += IMAGE_SIZEOF_SHORT_NAME;
	sectionHeader->Misc.VirtualSize = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	sectionHeader->VirtualAddress = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	sectionHeader->SizeOfRawData = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	sectionHeader->PointerToRawData = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	sectionHeader->PointerToRelocations = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	sectionHeader->PointerToLinenumbers = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);
	sectionHeader->NumberOfRelocations = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);
	sectionHeader->NumberOfLinenumbers = convertToWord(lpBuffer + cursor);
	cursor += sizeof(WORD);
	sectionHeader->Characteristics = convertToDword(lpBuffer + cursor);
	cursor += sizeof(DWORD);

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

	printf("section %d\n", sectionNo);
	for (int i = 0; i < NUMBER_OF_SECTION_CHARACTERISTICS; i++)
	{
		if (section_characteristics[i].isActive)
		{
			printf("%s\n", section_characteristics[i].flagName);
			section_characteristics[i].isActive = false; // after printing, revert it back to false, maybe I should use an array and keep information of each section 
		}
	}

	return cursor;
}

