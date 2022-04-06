# PE injection

## 主模块

```c
inject.c:main
```

接受命令行参数，执行对应的功能。

主要功能：

```shell
usage: inject filename [-o output] [-s shellcode] [-p pe2shellcode] [-v pe2shellcode_output] [-c]
```

- `-o` 指定输出文件名字，默认覆盖原文件
- `-s` 指定 shellcode 地址，默认 shellcode 为创建 txt 文件
- `-p` 指定 pe2shellcode 的 PE 文件，没有代表不使用 pe2shellcode
- `-v` 指定 pe2shellcode 输出 shellcode 的名字，默认为输入+ `"_sh.exe"`
- `-c` 表示尝试在代码空洞插入 shellcode

项目由 Visual Studio 2022 创建。

## PE 模块

### PE 文件解析

```c
void PEParse(PE_file* ppeFile, FILE* file);
```

- 函数功能：解析 PE 文件
- ppeFile: PE_file to write
- file: PE file to parse

### 新增代码节

```c
void insertNewCodeSection(PE_file* ppefile, BYTE* code, DWORD codeSize);
```

- ppefile: PE_file to process
- code: pointer to new section
- codeSize: size of new section

### 寻找最大代码空洞

```c
DWORD findLargestCave(PE_file* ppeFile, int* index);
```

- ppeFile: PE_file to process
- index: output section index
- return: size of the cave

### 向指定 File Offset 写内容

```c
void PEwrite(PE_file* ppeFile, DWORD fa, BYTE* src, DWORD len);
```

- ppeFile: ppeFile to process
- fa: file address

### 保存 PE 文件

```c
void PESave(PE_file* pefile, char* savePath);
```

## PE2SHELL 模块

### PE 文件转 shellcode

```c
size_t pe2sh(PE_file* ppeFile, char** shellcode, char* savePath);
```

- ppeFile: PE_file to process
- shellcode: pointer to shellcode address
- savePath: save file name of shellcode
- return: shellcode size

### stub 程序

`hldr32.asm`，实现了加载 DLL、引入函数解析、重定位。

编译：

```shell
yasm hldr32.asm -f bin -o stub32.bin
```

## shellcode 模块

### shellcode 文件夹

- shellcode_createfile.asm，功能为创建 txt 文件
- shellcode_opencalc.asm，功能为打开计算器

编译：

```shell
fasm shellcode_createfile.asm shellcode_createfile
fasm shellcode_opencalc.asm shellcode_opencalc.asm
```

### test shellcode

`testshell.c`，用于测试 shellcode

编译：

```c
gcc testshell.c -o testshell
```

## 测试模块

`test` 文件夹下

- `calc.exe` win10 计算器程序
- `calc_xp.exe` winxp 计算器程序
- `mype.exe` 弹窗程序
- `PEView.exe` PE 查看器
- `PEinjection.exe` PE 注入器，本项目生成的文件
- `stub32.bin` stub 程序

### 以 calc_xp.exe 为例演示功能

- 以新增节的方式插入默认 shellcode

```shell
.\PEinjection.exe .\calc_xp.exe -o newpe.exe
```

- 以填充代码空洞的方式插入默认 shellcode

```shell
.\PEinjection.exe .\calc_xp.exe -o newpe.exe -c
```

- 以新增节的方式插入 calc.exe 文件

```shell
.\PEinjection.exe .\calc_xp.exe -o newpe.exe -p calc.exe
```

