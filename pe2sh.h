#pragma once
#ifndef __PE2SH_H_
#define __PE2SH_H_
#include "pe.h"

size_t pe2sh(PE_file* ppeFile, char** shellcode, char* savePath);

#endif // !__PE2SH_H_
