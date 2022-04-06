#include "pe.h"
#include <string.h>
#include <stdio.h>

void overwriteHeader(BYTE* file, DWORD addr) {
	BYTE redir_code[] = "\x4D" //dec ebp
		"\x5A" //pop edx
		"\x45" //inc ebp
		"\x52" //push edx
		"\xE8\x00\x00\x00\x00" //call <next_line>
		"\x5B" // pop ebx
		"\x48\x83\xEB\x09" // sub ebx,9
		"\x53" // push ebx (Image Base)
		"\x48\x81\xC3" // add ebx,
		"\x59\x04\x00\x00" // value
		"\xFF\xD3" // call ebx
		"\xc3"; // ret
	size_t offset = sizeof(redir_code) - 8;

	memcpy(redir_code + offset, &addr, sizeof(DWORD));
	memcpy(file, redir_code, sizeof(redir_code));
}

DWORD readStubFile(BYTE** stub) {
	const char* stub32 = "./stub32.bin";
	FILE* file;
	errno_t err = fopen_s(&file, stub32, "rb");
	if (err) {
		perror("sub32.bin");
		exit(EXIT_FAILURE);
	}
	fseek(file, 0, SEEK_END);
	DWORD stubSize = ftell(file);
	fseek(file, 0, SEEK_SET);
	*stub = (BYTE*)malloc(stubSize);
	if (*stub == NULL) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	fread(*stub, 1, stubSize, file);
	fclose(file);
	return stubSize;
}

size_t pe2sh(PE_file* ppeFile, char **shellcode, char* savePath) {
	if (ppeFile->pimageNTHeaders->OptionalHeader.DataDirectory[5].VirtualAddress == 0) {
		printf("no relocation section found!\n");
		exit(EXIT_FAILURE);
	}
	DWORD imageSize = ppeFile->pimageNTHeaders->OptionalHeader.SizeOfImage;
	
	// read stub program
	BYTE* stub;
	DWORD stubSize = readStubFile(&stub);

	// new file
	// DWORD stubSizeAligned = align(stubSize, ppeFile->pimageNTHeaders->OptionalHeader.SectionAlignment);
	DWORD newfileSize = imageSize + stubSize;
	BYTE* newfile = (BYTE*)malloc(newfileSize);
	if (newfile == NULL) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	memset(newfile, 0, newfileSize);

	// copy sections to their virtual address
	WORD sectionNumbers = ppeFile->pimageNTHeaders->FileHeader.NumberOfSections;
	for (size_t i = 0; i < sectionNumbers; i++) {
		PIMAGE_SECTION_HEADER phdr = ppeFile->ppimageSectionHeader[i];
		if (phdr->SizeOfRawData == 0 || phdr->Misc.VirtualSize == 0) continue;
		LPVOID destAddr = phdr->VirtualAddress + (BYTE*)newfile;
		LPVOID rawAddr = phdr->PointerToRawData + (BYTE*)ppeFile->innerBuffer;
		DWORD copySize = phdr->SizeOfRawData;
		memcpy(destAddr, rawAddr, copySize);
	}

	// copy headers
	memcpy(newfile, ppeFile->innerBuffer, ppeFile->pimageNTHeaders->OptionalHeader.SizeOfHeaders);
	
	// parse new PE file
	PE_file newPEFile;
	newPEFile.innerBuffer = newfile;
	newPEFile.fileSize = newfileSize;
	_PEParse(&newPEFile);

	// overwrite headers
	// file alignment
	newPEFile.pimageNTHeaders->OptionalHeader.FileAlignment =
		newPEFile.pimageNTHeaders->OptionalHeader.SectionAlignment;
	// update section headers
	for (size_t i = 0; i < sectionNumbers; i++) {
		PIMAGE_SECTION_HEADER phdr = newPEFile.ppimageSectionHeader[i];
		phdr->Misc.VirtualSize = align(phdr->Misc.VirtualSize,
			newPEFile.pimageNTHeaders->OptionalHeader.SectionAlignment);
		phdr->PointerToRawData = phdr->VirtualAddress;
		phdr->SizeOfRawData = phdr->Misc.VirtualSize;
	}
	// copy stub program
	memcpy(newfile + imageSize, stub, stubSize);
	// overwrite DOS header
	overwriteHeader(newfile, imageSize);
	// save file
	PESave(&newPEFile, savePath);
	// free buffer
	free(stub);
	*shellcode = newfile;
	return newfileSize;
}
