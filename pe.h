#ifndef __PE_H_
#define __PE_H_
#include <Windows.h>
#include <stdio.h>
#define MAX_SECTIONS 128

typedef struct _PE_file {
	BYTE* innerBuffer;
	PIMAGE_DOS_HEADER pimageDOSHeader;
	PIMAGE_NT_HEADERS pimageNTHeaders;
	PIMAGE_SECTION_HEADER ppimageSectionHeader[MAX_SECTIONS];
	DWORD fileSize;
	BYTE* ppsection[MAX_SECTIONS];
} PE_file;

DWORD align(DWORD x, DWORD align);
void _PEParse(PE_file* ppeFile);
void PEParse(PE_file* ppeFile, FILE* file);
void PEFree(PE_file* pefile);
DWORD getImageBase(PE_file* ppeFile);
DWORD getEntryPoint(PE_file* ppeFile);
DWORD findLargestCave(PE_file* ppeFile, int* index);
void PEwrite(PE_file* ppeFile, DWORD fa, BYTE* src, DWORD len);
void insertNewCodeSection(PE_file* ppefile, BYTE* code, DWORD codeSize);
void PESave(PE_file* pefile, char* savePath);

#endif // !__PE_H_

