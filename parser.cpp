#include "pch.h"
#include <stdio.h>
#include <windows.h>
#include <winnt.h>

DWORD convertToDword( UINT8 *buffer)
{
	DWORD res = 0;
	DWORD test = sizeof(buffer);
	res += buffer[0];
	res += buffer[1] << 8;
	res += buffer[2] << 16;
	res += buffer[3] << 24;

	return res;
}

WORD convertToword(UINT8 *buffer)
{
	WORD res = 0;
	res += buffer[0];
	res += buffer[1] << 8;

	return res;
}

int main()
{
	DWORD elfanew = 0;	
	int numArgs = 0;
	DWORD dwordRef;
	DWORD cursor = 0;

	IMAGE_DOS_HEADER dosHeader;

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

	dosHeader.e_magic = convertToDword(lpBuffer);
	if (dosHeader.e_magic == 0x5a4d)
	{
		printf("MZ signature not found");
		exit(-1);
	}

	cursor += sizeof(WORD);

	dosHeader.e_cblp	   =  convertToDword(lpBuffer);
	dosHeader.e_cp		   =  convertToDword(lpBuffer);
	dosHeader.e_crlc	   =  convertToDword(lpBuffer);
	dosHeader.e_cparhdr	   =  convertToDword(lpBuffer);
	dosHeader.e_minalloc   =  convertToDword(lpBuffer);
	dosHeader.e_maxalloc   =  convertToDword(lpBuffer);
	dosHeader.e_ss		   =  convertToDword(lpBuffer);
	dosHeader.e_sp		   =  convertToDword(lpBuffer);
	dosHeader.e_csum	   =  convertToDword(lpBuffer);
	dosHeader.e_ip		   =  convertToDword(lpBuffer);
	dosHeader.e_cs		   =  convertToDword(lpBuffer);
	dosHeader.e_lfarlc	   =  convertToDword(lpBuffer);
	dosHeader.e_ovno	   =  convertToDword(lpBuffer);
	dosHeader.e_res[4];	
	dosHeader.e_oemid;
	dosHeader.e_oeminfo;
	dosHeader.e_res2[10];
	dosHeader.e_lfanew;



	elfanew = convertToDword(lpBuffer+0x3c);

	return 0;
}

