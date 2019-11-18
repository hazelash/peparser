#include "stdafx.h"
#include "../peparser/ds.h"
#include "../peparser/functions.h"
#include <stdio.h>
#include <windows.h>
#include <winnt.h>

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

	UINT8 *lpBuffer = (UINT8 *)malloc(fileSize);
	if (lpBuffer == NULL)
	{
		printf("unexpected result from malloc");
		exit(-1);
	}

	BOOL res = ReadFile(hSrcFile, lpBuffer, fileSize, &dwordRef, 0);
	if (dwordRef != fileSize || res == FALSE)
	{
		printf("unexpected result from ReadFile");
		exit(-1);
	}

	memset(&dosHeader, 0x00, sizeof(IMAGE_DOS_HEADER));
	cursor = parseDosHeader(&dosHeader, lpBuffer, cursor);

	printDosHeader(&dosHeader, 0);

	DWORD offsetToDosStub = cursor;
	DWORD offsetToNewPe = dosHeader.e_lfanew;
	cursor = offsetToNewPe;

	memset(&ifh, 0x00, sizeof(IMAGE_FILE_HEADER));
	cursor = parseImageFileHeader(&ifh, lpBuffer, cursor);

	// Note that the size of the optional header is not fixed. 
	// The SizeOfOptionalHeader field in the COFF header must be used to validate that a probe into the file for a particular data directory does not go beyond SizeOfOptionalHeader. 
	DWORD offsetToIOH = cursor;
	WORD iohMagic = convertToWord(lpBuffer + cursor);

	if (iohMagic == 0x10b)
	{
		memset(&ioh32, 0x00, sizeof(IMAGE_OPTIONAL_HEADER32));
		cursor = parseImageOptionalHeader32(&ioh32, lpBuffer, cursor, ifh.SizeOfOptionalHeader);
		printIOH32(&ioh32);
	}

	else if (iohMagic == 0x20b)
	{
		memset(&ioh64, 0x00, sizeof(IMAGE_OPTIONAL_HEADER64));
		cursor = parseImageOptionalHeader64(&ioh64, lpBuffer, cursor, ifh.SizeOfOptionalHeader);
		printIOH64(&ioh64);
	}

	else
	{
		printf("Invalid Magic value in IMAGE_OPTIONAL_HEADER");
		exit(-1);
	}

	IMAGE_SECTION_HEADER *ish = NULL;

	if (ifh.NumberOfSections != 0)
	{
		ish = (IMAGE_SECTION_HEADER *)malloc(sizeof(IMAGE_SECTION_HEADER) * ifh.NumberOfSections);
	}
	

	for (int i = 0; i < ifh.NumberOfSections; i++)
	{
		cursor = parseSectionHeader(&ish[i], lpBuffer, cursor, i);
	}



	return 0;
}

