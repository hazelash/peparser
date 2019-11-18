#include "stdafx.h"
#include "../peparser/ds.h"
#include "../peparser/functions.h"
#include <stdio.h>
#include <windows.h>
#include <winnt.h>

#define MIN_READ_SIZE 0x400

int main()
{
	DWORD elfanew = 0;
	int numArgs = 0;
	DWORD dwordRef;
	DWORD cursor = 0;

	IMAGE_DOS_HEADER dosHeader;
	IMAGE_FILE_HEADER ifh;

	IMAGE_OPTIONAL_HEADER32 ioh32;
	IMAGE_OPTIONAL_HEADER64 ioh64;

	LPCWSTR cmdline = GetCommandLineW();

	LPWSTR *args = CommandLineToArgvW(cmdline, &numArgs);
	if (numArgs != 2 || args == NULL)
	{
		printf("unexpected result from CommandLineToArgvW");
		exit(-1);
	}

	HANDLE hSrcFile = CreateFileW(args[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hSrcFile == INVALID_HANDLE_VALUE)
	{
		printf("unexpected result from CreateFileW");
		exit(-1);
	}

	DWORD fileSize = GetFileSize(hSrcFile, &dwordRef);
	if (fileSize == INVALID_FILE_SIZE)
	{
		printf("unexpected result from GetFileSize");
		exit(-1);
	}

	if ( fileSize < MIN_READ_SIZE)
	{
		printf("The size of file seems be too small. (minimum)");
		exit(-1);
	}

	UINT8 *lpBuffer = (UINT8 *)malloc(MIN_READ_SIZE);

	if (lpBuffer == NULL)
	{
		printf("unexpected result from malloc");
		exit(-1);
	}

	BOOL res = ReadFile(hSrcFile, lpBuffer, MIN_READ_SIZE, &dwordRef, 0);
	if (dwordRef != MIN_READ_SIZE || res == FALSE)
	{
		printf("unexpected result from ReadFile");
		exit(-1);
	}

	memset(&dosHeader, 0x00, sizeof(IMAGE_DOS_HEADER));
	cursor = parseDosHeader(&dosHeader, lpBuffer, cursor);

	printDosHeader(&dosHeader, 0);

	DWORD offsetToDosStub = cursor;
	DWORD offsetToNewPe = dosHeader.e_lfanew;
	DWORD sectionAlignment = 0;
	cursor = offsetToNewPe;

	if ( cursor + sizeof(IMAGE_FILE_HEADER) > MIN_READ_SIZE )
	{
		printf("Not sufficient buffer to read IMAGE_FILE_HEADER");
		exit(-1);
	}

	memset(&ifh, 0x00, sizeof(IMAGE_FILE_HEADER));
	cursor = parseImageFileHeader(&ifh, lpBuffer, cursor);
	printFileHeader(&ifh);

	// Note that the size of the optional header is not fixed. 
	// The SizeOfOptionalHeader field in the COFF header must be used to validate that a probe into the file for a particular data directory does not go beyond SizeOfOptionalHeader. 
	DWORD offsetToIOH = cursor;

	if (cursor + sizeof(DWORD) > MIN_READ_SIZE)
	{
		printf("Not sufficient buffer to read Optional_Magic");
		exit(-1);
	}
	
	WORD iohMagic = convertToWord(lpBuffer + cursor);

	if (iohMagic == 0x10b)
	{
		if (cursor + sizeof(IMAGE_OPTIONAL_HEADER32) > MIN_READ_SIZE)
		{
			printf("Not sufficient buffer to read IMAGE_OPTIONAL_HEADER32");
			exit(-1);
		}

		memset(&ioh32, 0x00, sizeof(IMAGE_OPTIONAL_HEADER32));
		cursor = parseImageOptionalHeader32(&ioh32, lpBuffer, cursor, ifh.SizeOfOptionalHeader);
		printIOH32(&ioh32);
		sectionAlignment = ioh32.SectionAlignment;
	}

	else if (iohMagic == 0x20b)
	{
		if (cursor + sizeof(IMAGE_OPTIONAL_HEADER64) > MIN_READ_SIZE)
		{
			printf("Not sufficient buffer to read IMAGE_OPTIONAL_HEADER64");
			exit(-1);
		}

		memset(&ioh64, 0x00, sizeof(IMAGE_OPTIONAL_HEADER64));
		cursor = parseImageOptionalHeader64(&ioh64, lpBuffer, cursor, ifh.SizeOfOptionalHeader);
		printIOH64(&ioh64);
		sectionAlignment = ioh64.SectionAlignment;
	}

	else
	{
		printf("Invalid Magic value in IMAGE_OPTIONAL_HEADER");
		exit(-1);
	}

	IMAGE_SECTION_HEADER *ish = NULL;

	if (ifh.NumberOfSections != 0)
	{
		if (cursor + sizeof(IMAGE_SECTION_HEADER) * ifh.NumberOfSections > MIN_READ_SIZE)
		{
			printf("Not sufficient buffer to read IMAGE_SECTION_HEADER");
			exit(-1);
		}

		ish = (IMAGE_SECTION_HEADER *)malloc(sizeof(IMAGE_SECTION_HEADER) * ifh.NumberOfSections);
	}

	for (int i = 0; i < ifh.NumberOfSections; i++)
	{
		cursor = parseSectionHeader(&ish[i], lpBuffer, cursor, i);
		printSectionHeader(&ish[i], i);
	}

	free(lpBuffer);
	
	printBigLine();

	DWORD rawSizeSpecifiedInHeader = ish[ifh.NumberOfSections - 1].PointerToRawData + ish[ifh.NumberOfSections - 1].SizeOfRawData;
	DWORD memorySpaceRequired = ceiling(ish[ifh.NumberOfSections - 1].VirtualAddress + ish[ifh.NumberOfSections - 1].Misc.VirtualSize, sectionAlignment);

	if (fileSize == rawSizeSpecifiedInHeader)
	{
		printf("Ready to load the file");
		//exit(-1);
	} 
	else if (fileSize < rawSizeSpecifiedInHeader)
	{
		printf("The File is incomplete / corrupted");
		exit(-1);
	} 
	else if (fileSize > rawSizeSpecifiedInHeader)
	{
		// maybe consider file align 
		printf("The file has overlay data (%08x bytes)", fileSize- rawSizeSpecifiedInHeader);
		//exit(-1);
	}

	lpBuffer = (UINT8 *)malloc(fileSize);
	memset(lpBuffer, 0x00, fileSize);

	SetFilePointer(hSrcFile, 0, 0, 0);

	res = ReadFile(hSrcFile, lpBuffer, fileSize, &dwordRef, 0);
	if (dwordRef != fileSize || res == FALSE)
	{
		printf("unexpected result from ReadFile (full)");
		exit(-1);
	}

	// map the file as it should be aligned in the memory

	// first section

	// ... section x

	// import

	// export

	if (!CloseHandle(hSrcFile))
	{
		printf("[ERROR] Closing Handle.\n");
		exit(-1);
	}

	return 0;
}

