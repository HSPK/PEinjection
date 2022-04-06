#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include "pe.h"

#define DEBUG 1
#if(DEBUG == 1)
#define DBG(fmt, ...) \
	printf(fmt, __VA_ARGS__)
#else
#define DBG(fmt, ...)
#endif // DEBUG

#define CEIL(x, y) (((x) + (y) - 1) / (y))

DWORD align(DWORD x, DWORD align) {
	return (x + align - 1) / align * align;
}

inline WORD getSectionNumbers(PE_file* ppeFile) {
	return ppeFile->pimageNTHeaders->FileHeader.NumberOfSections;
}

inline DWORD getSectionHeadersOffset(PE_file* ppeFile) {
	return (DWORD)(ppeFile->pimageDOSHeader->e_lfanew +
		sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) +
		ppeFile->pimageNTHeaders->FileHeader.SizeOfOptionalHeader);
}

DWORD getImageBase(PE_file* ppeFile) {
	return ppeFile->pimageNTHeaders->OptionalHeader.ImageBase;
}

DWORD getEntryPoint(PE_file* ppeFile) {
	return ppeFile->pimageNTHeaders->OptionalHeader.AddressOfEntryPoint;
}

DWORD findLargestCave(PE_file* ppeFile, int *index) {
	WORD sectionNumbers = getSectionNumbers(ppeFile);
	DWORD fileAlignment = ppeFile->pimageNTHeaders->OptionalHeader.FileAlignment;
	DWORD caveSize = 0;
	for (int i = 0; i < sectionNumbers; i++) {
		if ((ppeFile->ppimageSectionHeader[i]->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;
		DWORD virtualSize = ppeFile->ppimageSectionHeader[i]->Misc.VirtualSize;
		DWORD rawSize = ppeFile->ppimageSectionHeader[i]->SizeOfRawData;
		DWORD alignedSize = align(rawSize, fileAlignment);
		if (virtualSize > alignedSize) continue;
		if (alignedSize - virtualSize > caveSize) {
			*index = i;
			caveSize = alignedSize - virtualSize;
		}
	}
	return caveSize;
}

void PEwrite(PE_file* ppeFile, DWORD fa, BYTE* src, DWORD len) {
	memcpy(ppeFile->innerBuffer + fa, src, len);
}

void readToInnerBuffer(PE_file* ppeFile, FILE* file) {
	// save PE to inner buffer
	fseek(file, 0, SEEK_END);
	long fileSize = ftell(file);
	ppeFile->fileSize = fileSize;
	ppeFile->innerBuffer = (char*)malloc(fileSize * sizeof(char));
	if (ppeFile->innerBuffer == NULL) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	fseek(file, 0, SEEK_SET);
	fread(ppeFile->innerBuffer, 1, fileSize, file);
	fclose(file);
}

void parseDOSHeader(PE_file* ppeFile) {
	ppeFile->pimageDOSHeader = (PIMAGE_DOS_HEADER)ppeFile->innerBuffer;
	if (ppeFile->pimageDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		fprintf(stderr, "invalid DOS magic: %x", ppeFile->pimageDOSHeader->e_magic);
		exit(EXIT_FAILURE);
	}
}

void parseNTHeaders(PE_file* ppeFile) {
	ppeFile->pimageNTHeaders = (PIMAGE_NT_HEADERS)((int)ppeFile->innerBuffer + ppeFile->pimageDOSHeader->e_lfanew);
	if (ppeFile->pimageNTHeaders->Signature != IMAGE_NT_SIGNATURE) {
		fprintf(stderr, "invalid NT headers signature: %x", ppeFile->pimageNTHeaders->Signature);
		exit(EXIT_FAILURE);
	}
	if (ppeFile->pimageNTHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
		fprintf(stderr, "invalid Optional headers magic: %x", ppeFile->pimageNTHeaders->OptionalHeader.Magic);
		exit(EXIT_FAILURE);
	}
}

void parseSections(PE_file* ppeFile) {
	size_t sectionNumbers = getSectionNumbers(ppeFile);
	void* sectionHeadersBase = (void*)((int)getSectionHeadersOffset(ppeFile) + (int)ppeFile->innerBuffer);
	for (size_t i = 0; i < sectionNumbers; i++) {
		ppeFile->ppimageSectionHeader[i] = (PIMAGE_SECTION_HEADER)sectionHeadersBase + i;
	}
	for (size_t i = 0; i < sectionNumbers; i++) {
		void* sectionBase = (void*)((int)ppeFile->ppimageSectionHeader[i]->PointerToRawData + (int)ppeFile->innerBuffer);
		ppeFile->ppsection[i] = sectionBase;
	}
}

void _PEParse(PE_file* ppeFile) {
	DBG("parsing DOS Header...\n");
	parseDOSHeader(ppeFile);
	DBG("parsing NT headers...\n");
	parseNTHeaders(ppeFile);
	DBG("parsing section headers...\n");
	parseSections(ppeFile);
	DBG("parsing finished...\n");
}

void PEParse(PE_file *ppeFile, FILE *file) {
	readToInnerBuffer(ppeFile, file);
	_PEParse(ppeFile);
}

void insertNewSectionHeader(PE_file* ppefile, PIMAGE_SECTION_HEADER phdr) {
	DWORD destOffset = getSectionHeadersOffset(ppefile)
		+ getSectionNumbers(ppefile) * sizeof(IMAGE_SECTION_HEADER);
	BYTE* destAddr = ppefile->innerBuffer + destOffset;
	if (destOffset + sizeof(IMAGE_SECTION_HEADER) > ppefile->pimageNTHeaders->OptionalHeader.SizeOfHeaders) {
		fprintf(stderr, "addr out of limit\n");
		exit(EXIT_FAILURE);
	}
	memcpy(destAddr, phdr, sizeof(IMAGE_SECTION_HEADER));
	ppefile->ppimageSectionHeader[getSectionNumbers(ppefile)] = (PIMAGE_SECTION_HEADER)destAddr;
	ppefile->pimageNTHeaders->FileHeader.NumberOfSections += 1;
}

void insertNewCodeSection(PE_file* ppefile, BYTE* code, DWORD codeSize) {
	size_t fileAlignment = ppefile->pimageNTHeaders->OptionalHeader.FileAlignment;
	size_t sectionAlignment = ppefile->pimageNTHeaders->OptionalHeader.SectionAlignment;
	size_t rawSize = CEIL(codeSize, fileAlignment) * fileAlignment;
	size_t codeSizeAligned = CEIL(codeSize, sectionAlignment) * sectionAlignment;
	size_t sectionNumbers = getSectionNumbers(ppefile);
	DWORD destVirtualAddr = ppefile->ppimageSectionHeader[sectionNumbers - 1]->VirtualAddress +
		CEIL(ppefile->ppimageSectionHeader[sectionNumbers - 1]->Misc.VirtualSize, sectionAlignment) *
		sectionAlignment;
	DWORD pointerToRawData = ppefile->ppimageSectionHeader[sectionNumbers - 1]->PointerToRawData +
		ppefile->ppimageSectionHeader[sectionNumbers - 1]->SizeOfRawData;
	IMAGE_SECTION_HEADER hdr = {
		.Name = {'.', 'n', 'e', 'w', 0, 0, 0, 0},
		.Misc.VirtualSize = rawSize,
		.VirtualAddress = destVirtualAddr,
		.SizeOfRawData = rawSize,
		.PointerToRawData = pointerToRawData,
		.PointerToRelocations = 0,
		.PointerToLinenumbers = 0,
		.NumberOfLinenumbers = 0,
		.NumberOfRelocations = 0,
		.Characteristics =
						IMAGE_SCN_CNT_CODE |
						IMAGE_SCN_MEM_EXECUTE |
						IMAGE_SCN_MEM_READ 
					  | IMAGE_SCN_MEM_WRITE
	};
	insertNewSectionHeader(ppefile, &hdr);
	BYTE* oldBuffer = ppefile->innerBuffer;
	ppefile->innerBuffer = realloc(ppefile->innerBuffer, ppefile->fileSize + rawSize);
	if (ppefile->innerBuffer == NULL) {
		perror("realloc");
		exit(EXIT_FAILURE);
	}
	if (ppefile->innerBuffer != oldBuffer) {
		DBG("reparsing...\n");
		_PEParse(ppefile);
	}
	memset(ppefile->innerBuffer + ppefile->fileSize, 0, rawSize);
	memcpy(ppefile->innerBuffer + ppefile->fileSize, code, codeSize);
	ppefile->fileSize += rawSize;
	ppefile->pimageNTHeaders->OptionalHeader.SizeOfImage += codeSizeAligned;
	DBG("insert finished, reparsing sections...\n");
	parseSections(ppefile);
}

void PESave(PE_file* pefile, char* savePath) {
	FILE* fp;
	fopen_s(&fp, savePath, "wb");
	if (fp == NULL) {
		perror("fopen_s");
		exit(EXIT_FAILURE);
	}
	fwrite(pefile->innerBuffer, 1, pefile->fileSize, fp);
	fclose(fp);
}

void PEFree(PE_file* pefile) {
	free(pefile->innerBuffer);
}