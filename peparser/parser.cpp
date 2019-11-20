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
	int nNumArgs = 0;
	DWORD dwRefSize;
	DWORD dwCursor = 0;

	IMAGE_DOS_HEADER stDosHeader;
	IMAGE_FILE_HEADER stFileHeader;

	IMAGE_OPTIONAL_HEADER32 stOptionalHeader32;
	IMAGE_OPTIONAL_HEADER64 stOptionalHeader64;

	LPCWSTR cmdline = GetCommandLineW();

	LPWSTR *args = CommandLineToArgvW(cmdline, &nNumArgs);
	if (nNumArgs != 2 || args == NULL)
	{
		printf("unexpected result from CommandLineToArgvW\n");
		exit(-1);
	}

	HANDLE hSrcFile = CreateFileW(args[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hSrcFile == INVALID_HANDLE_VALUE)
	{
		printf("unexpected result from CreateFileW\n");
		exit(-1);
	}

	DWORD fileSize = GetFileSize(hSrcFile, &dwRefSize);
	if (fileSize == INVALID_FILE_SIZE)
	{
		printf("unexpected result from GetFileSize\n");
		exit(-1);
	}

	if ( fileSize < MIN_READ_SIZE)
	{
		printf("The size of file seems be too small. (minimum)\n");
		exit(-1);
	}

	UINT8 *lpBuffer = (UINT8 *)malloc(fileSize);

	if (lpBuffer == NULL)
	{
		printf("unexpected result from malloc\n");
		exit(-1);
	}

	BOOL res = ReadFile(hSrcFile, lpBuffer, fileSize, &dwRefSize, 0);
	if (dwRefSize != fileSize || res == FALSE)
	{
		printf("unexpected result from ReadFile\n");
		exit(-1);
	}

	memset(&stDosHeader, 0x00, sizeof(IMAGE_DOS_HEADER));
	dwCursor = parseDosHeader(&stDosHeader, lpBuffer, dwCursor);

	printDosHeader(&stDosHeader, 0);

	DWORD offsetToDosStub = dwCursor;
	DWORD offsetToNewPe = stDosHeader.e_lfanew;
	DWORD dwMemAlign = 0;
	dwCursor = offsetToNewPe;

	if ( dwCursor + sizeof(IMAGE_FILE_HEADER) > fileSize)
	{
		printf("Not sufficient buffer to read IMAGE_FILE_HEADER\n");
		exit(-1);
	}

	memset(&stFileHeader, 0x00, sizeof(IMAGE_FILE_HEADER));
	dwCursor = parseImageFileHeader(&stFileHeader, lpBuffer, dwCursor);
	printFileHeader(&stFileHeader);

	// Note that the size of the optional header is not fixed. 
	// The SizeOfOptionalHeader field in the COFF header must be used to validate that a probe into the file for a particular data directory does not go beyond SizeOfOptionalHeader. 
	DWORD offsetToIOH = dwCursor;

	if (dwCursor + sizeof(DWORD) > fileSize)
	{
		printf("Not sufficient buffer to read Optional_Magic\n");
		exit(-1);
	}
	
	WORD iohMagic = convertToWord(lpBuffer + dwCursor);

	if (iohMagic == 0x10b)
	{
		if (dwCursor + sizeof(IMAGE_OPTIONAL_HEADER32) > fileSize)
		{
			printf("Not sufficient buffer to read IMAGE_OPTIONAL_HEADER32\n");
			exit(-1);
		}

		memset(&stOptionalHeader32, 0x00, sizeof(IMAGE_OPTIONAL_HEADER32));
		dwCursor = parseImageOptionalHeader32(&stOptionalHeader32, lpBuffer, dwCursor, stFileHeader.SizeOfOptionalHeader);
		printOptionalHeader32(&stOptionalHeader32);
		dwMemAlign = stOptionalHeader32.SectionAlignment;
	}

	else if (iohMagic == 0x20b)
	{
		if (dwCursor + sizeof(IMAGE_OPTIONAL_HEADER64) > fileSize)
		{
			printf("Not sufficient buffer to read IMAGE_OPTIONAL_HEADER64\n");
			exit(-1);
		}

		memset(&stOptionalHeader64, 0x00, sizeof(IMAGE_OPTIONAL_HEADER64));
		dwCursor = parseImageOptionalHeader64(&stOptionalHeader64, lpBuffer, dwCursor, stFileHeader.SizeOfOptionalHeader);
		printOptionalHeader64(&stOptionalHeader64);
		dwMemAlign = stOptionalHeader64.SectionAlignment;
	}

	else
	{
		printf("Invalid Magic value in IMAGE_OPTIONAL_HEADER\n");
		exit(-1);
	}

	IMAGE_SECTION_HEADER *ish = NULL;

	if (stFileHeader.NumberOfSections != 0)
	{
		if (dwCursor + sizeof(IMAGE_SECTION_HEADER) * stFileHeader.NumberOfSections > fileSize)
		{
			printf("Not sufficient buffer to read IMAGE_SECTION_HEADER\n");
			exit(-1);
		}

		ish = (IMAGE_SECTION_HEADER *)malloc(sizeof(IMAGE_SECTION_HEADER) * stFileHeader.NumberOfSections);
	}

	for (int i = 0; i < stFileHeader.NumberOfSections; i++)
	{
		dwCursor = parseSectionHeader(&ish[i], lpBuffer, dwCursor, i);
		printSectionHeader(&ish[i], i);
	}

	printBigLine();

	DWORD dwTotalRawSize = ish[stFileHeader.NumberOfSections - 1].PointerToRawData + ish[stFileHeader.NumberOfSections - 1].SizeOfRawData;
	DWORD dwTotalVirtualSize = ceiling(ish[stFileHeader.NumberOfSections - 1].VirtualAddress + ish[stFileHeader.NumberOfSections - 1].Misc.VirtualSize, dwMemAlign);

	if (fileSize == dwTotalRawSize)
	{
		printf("Ready to load the file\n");
		//exit(-1);
	} 
	else if (fileSize < dwTotalRawSize)
	{
		printf("The File is incomplete / corrupted\n");
		exit(-1);
	} 
	else if (fileSize > dwTotalRawSize)
	{
		// maybe consider file align 
		printf("The file has overlay data (%08x bytes)\n", fileSize - dwTotalRawSize);
		//exit(-1);
	}

	// map the file as it should be aligned in the memory (becomes easier to navigate with RVA)
	LPVOID lpvBaseAddr = NULL;
	DWORD dwNewBase = NULL;
	DWORD dwOffsetMem = 0;
	DWORD dwOffsetFile = 0;
	DWORD dwTemp = 0;

	lpvBaseAddr = VirtualAlloc(0, dwTotalVirtualSize, MEM_COMMIT, PAGE_READWRITE);
	if (lpvBaseAddr == NULL)
	{
		printf("[ERROR] VirtualAlloc\n");
		exit(-1);
	}

	// contents just before the first section
	memcpy(lpvBaseAddr, lpBuffer, ish[0].PointerToRawData);
	dwOffsetMem += max(ish[0].PointerToRawData, dwMemAlign);

	// Copy contents of each section 
	for (int i = 0; i < stFileHeader.NumberOfSections; i++)
	{
		dwNewBase = addDwordToLpvoid(lpvBaseAddr, dwOffsetMem);
		if ((DWORD)lpvBaseAddr+dwTotalVirtualSize < dwNewBase)
		{
			printf("[ERROR] out of bound [1]\n");
			exit(-1);
		}

		dwOffsetFile = ish[i].PointerToRawData;
		memcpy((LPVOID)dwNewBase, lpBuffer + dwOffsetFile, ish[i].SizeOfRawData);
		dwOffsetMem += ceiling(ish[i].Misc.VirtualSize, dwMemAlign);
	}

	DWORD dwIDTSize = 0;

	// import
	if (iohMagic == 0x10b)
	{
		dwCursor = addDwordToLpvoid(lpvBaseAddr, stOptionalHeader32.DataDirectory[1].VirtualAddress);
		if ((DWORD)lpvBaseAddr + dwTotalVirtualSize < dwCursor)
		{
			printf("[ERROR] out of bound [2]\n");
			exit(-1);
		}
		dwIDTSize = stOptionalHeader32.DataDirectory[1].Size;
	}
	else if (iohMagic == 0x20b)
	{
		dwCursor = addDwordToLpvoid(lpvBaseAddr, stOptionalHeader64.DataDirectory[1].VirtualAddress);
		if ((DWORD)lpvBaseAddr + dwTotalVirtualSize < dwCursor)
		{
			printf("[ERROR] out of bound [2-2]\n");
			exit(-1);
		}
		dwIDTSize = stOptionalHeader64.DataDirectory[1].Size;
	}
	else 
	{
		// this won't happen but just keeping
	}

	// just testing the first iteration now 
	IMAGE_IMPORT_DESCRIPTOR stIDT;

	memcpy(&stIDT.OriginalFirstThunk, (LPVOID)dwCursor, sizeof(DWORD));
	dwCursor += sizeof(DWORD);
	memcpy(&stIDT.TimeDateStamp, (LPVOID)(dwCursor), sizeof(DWORD));
	dwCursor += sizeof(DWORD);
	memcpy(&stIDT.ForwarderChain, (LPVOID)(dwCursor), sizeof(DWORD));
	dwCursor += sizeof(DWORD);
	memcpy(&stIDT.Name, (LPVOID)(dwCursor), sizeof(DWORD));
	dwCursor += sizeof(DWORD);
	memcpy(&stIDT.FirstThunk, (LPVOID)(dwCursor), sizeof(DWORD));
	dwCursor += sizeof(DWORD);

	printf("%-36s %08x\n", "[1]", stIDT.OriginalFirstThunk);
	printf("%-36s %08x\n", "[1]", stIDT.TimeDateStamp);
	printf("%-36s %08x\n", "[1]", stIDT.ForwarderChain);
	printf("%-36s %08x\n", "[1]", stIDT.Name);
	printf("%-36s %08x\n", "[1]", stIDT.FirstThunk);

	// export

	// rsrc

	if (!CloseHandle(hSrcFile))
	{
		printf("[ERROR] Closing Handle.\n");
		exit(-1);
	}

	return 0;
}

