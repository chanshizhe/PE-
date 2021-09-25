#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include <tchar.h>
#include <ctime>


//定义结构体存放有关信息
typedef struct MAP_FILE_STRUCT
{
	HANDLE hFile;		//文件句柄
	HANDLE hMapping;	//映射文件句柄
	LPVOID ImageBase;	//映像基址
}MAP_FILE_STRUCT, *PMAP_FILE_STRUCT;

MAP_FILE_STRUCT pstMapFile = { nullptr, nullptr, nullptr };


//加载文件
bool LoadFile(LPTSTR IpFileName, PMAP_FILE_STRUCT pstMapFile)
{
	if (IpFileName == nullptr)
	{
		return FALSE;
	}
	HANDLE hFile;
	HANDLE hMapping;
	LPVOID ImageBase;

	memset(pstMapFile, 0, sizeof(MAP_FILE_STRUCT));//内存初始化

	//只读方式打开文件，返回文件句柄
	hFile = CreateFile(IpFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (!hFile)
	{
		return FALSE;
	}

	//创建内存映射文件对象
	hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, 0);
	if (!hMapping)
	{
		CloseHandle(hFile);
		return FALSE;
	}

	//创建内存映射文件的视图
	ImageBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	if (!ImageBase)
	{
		CloseHandle(hFile);
		CloseHandle(hMapping);
		return FALSE;
	}
	pstMapFile->hFile = hFile;
	pstMapFile->hMapping = hMapping;
	pstMapFile->ImageBase = ImageBase;
	return TRUE;
}


//回收资源
void UnLoadFile(PMAP_FILE_STRUCT pstMapFile)
{
	if (pstMapFile->hFile)
	{
		CloseHandle(pstMapFile->hFile);
	}

	if (pstMapFile->hMapping)
	{
		CloseHandle(pstMapFile->hMapping);
	}

	if (pstMapFile->ImageBase)
	{
		//撤销映射并使用CloseHandle函数关闭内存映射文件对象句柄
		UnmapViewOfFile(pstMapFile->ImageBase);
	}
}


//检查文件格式
bool IsPEFile(LPVOID ImageBase)
{
	PIMAGE_DOS_HEADER pHD = NULL;
	PIMAGE_NT_HEADERS pNtH = NULL;

	if (!ImageBase)		//判断文件映像基址
	{
		return FALSE;
	}
	//判断起始位置是否为MZ
	pHD = (PIMAGE_DOS_HEADER)ImageBase;
	if (pHD->e_magic != IMAGE_DOS_SIGNATURE)	
	{
		return FALSE;
	}
	//判断PE头是否为PE00
	pNtH = (PIMAGE_NT_HEADERS32)((DWORD)pHD + pHD->e_lfanew);	
	if (pNtH->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}
	return TRUE;
}

//读取DosHeader、NtHeader、FileHeader、OptionalHeader和SectionHeader里的内容
//指向IMAGE_Dos_HEADER的结构指针
PIMAGE_DOS_HEADER GetDosHeader(LPVOID ImageBase)
{
	PIMAGE_DOS_HEADER pHD = NULL;
	if (!IsPEFile(ImageBase))
	{
		return NULL;
	}

	pHD = (PIMAGE_DOS_HEADER)ImageBase;
	return pHD;
}

//获取NtHeader
PIMAGE_NT_HEADERS GetNtHeaders(LPVOID ImageBase)
{
	PIMAGE_DOS_HEADER pHD = NULL;
	PIMAGE_NT_HEADERS pNtH = NULL;

	if (!IsPEFile(ImageBase))
	{
		return NULL;
	}

	pHD = (PIMAGE_DOS_HEADER)ImageBase;
	pNtH = (PIMAGE_NT_HEADERS)((DWORD)pHD + pHD->e_lfanew);
	return pNtH;
}

//指向IMAGE_FILE_HEADER的结构指针
PIMAGE_FILE_HEADER WINAPI GetFileHeader(LPVOID ImageBase)
{
	PIMAGE_NT_HEADERS pNtH = NULL;
	PIMAGE_FILE_HEADER pFH = NULL;
	pNtH = GetNtHeaders(ImageBase);
	if (!pNtH)
	{
		return NULL;
	}
	pFH = &pNtH->FileHeader;
	return pFH;
}

//指向IMAGE_OPTIONAL_HEADER的结构指针
PIMAGE_OPTIONAL_HEADER WINAPI GetOptionalHeader(LPVOID ImageBase)
{
	PIMAGE_NT_HEADERS pNtH = NULL;
	PIMAGE_OPTIONAL_HEADER pOH = NULL;
	pNtH = GetNtHeaders(ImageBase);
	if (!pNtH)
	{
		return NULL;
	}
	pOH = &pNtH->OptionalHeader;
	return pOH;
}


//指向IMAGE_SECTION_HEADER的结构指针
PIMAGE_SECTION_HEADER WINAPI GetSectionHeader(LPVOID ImageBase)
{
	PIMAGE_NT_HEADERS pNtH = NULL;
	PIMAGE_SECTION_HEADER pSH = NULL;
	pNtH = GetNtHeaders(ImageBase);
	if (!pNtH)
	{
		return NULL;
	}
	pSH = (PIMAGE_SECTION_HEADER)((int)pNtH + sizeof(pNtH->Signature) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER));
	return pSH;
}

void ShowRVAInfo(PMAP_FILE_STRUCT pstMapFile)
{
	int i;


	PIMAGE_DOS_HEADER pHD = GetDosHeader(pstMapFile->ImageBase);
	PIMAGE_NT_HEADERS pNtH = GetNtHeaders(pstMapFile->ImageBase);
	PIMAGE_FILE_HEADER pFH = GetFileHeader(pstMapFile->ImageBase);
	PIMAGE_OPTIONAL_HEADER pOH = GetOptionalHeader(pstMapFile->ImageBase);
	PIMAGE_SECTION_HEADER pSH = GetSectionHeader(pstMapFile->ImageBase);

	printf("毛月恒计算出的IMAGE_DOS_HEADER_RAV:%d\n", (int)pHD - (int)(pstMapFile->ImageBase));
	printf("毛月恒计算出的IMAGE_NT_HEADER_RAV:%d\n", (int)pNtH - (int)(pstMapFile->ImageBase));
	printf("毛月恒计算出的IMAGE_File_HEADER_RAV:%d\n", (int)pFH - (int)(pstMapFile->ImageBase));
	printf("毛月恒计算出的IMAGE_OPTIONAL_HEADER_RAV:%d\n", (int)pOH - (int)(pstMapFile->ImageBase));

	for (i = 0; i < pFH->NumberOfSections; i++)
	{
		pSH = GetSectionHeader(pstMapFile->ImageBase);
		pSH = (PIMAGE_SECTION_HEADER)((int)pSH + sizeof(IMAGE_SECTION_HEADER)*i);
		printf("毛月恒计算出的%s_RAV:%d\n",pSH->Name, (int)pSH - (int)(pstMapFile->ImageBase));
	}
	printf("\n");
}



//将FileHeader、OptionalHeader和SectionHeader的信息以十六进制的形式显示出来
void ShowHeaderInfo(PMAP_FILE_STRUCT pstMapFile)
{
	int i;
	char strTmp[1024] = { 0 };
	PIMAGE_DOS_HEADER pHD = nullptr;
	PIMAGE_NT_HEADERS pNtH = nullptr;
	PIMAGE_FILE_HEADER pFH = nullptr;
	PIMAGE_OPTIONAL_HEADER pOH = nullptr;
	PIMAGE_SECTION_HEADER pSH = nullptr;

	pHD = GetDosHeader(pstMapFile->ImageBase);
	if (!pHD)
	{
		printf("毛月恒提醒：获取Dos头失败!\n");
		return;
	}
	char* strDosHeaderFormat = "\
毛月恒计算出的IMAGE_DOS_HEADER:\n\
e_magic:%04X\n\
e_lfanew:%08X\n\n\
";
	sprintf(strTmp, strDosHeaderFormat, pHD->e_magic, pHD->e_lfanew);
	printf("%s", strTmp);
	memset(strTmp, 0, sizeof(strTmp));




	pNtH = GetNtHeaders(pstMapFile->ImageBase);
	if (!pNtH)
	{
		printf("毛月恒提醒：获取NT头失败!\n");
		return;
	}
	char* strNTHeaderFormat = "\
毛月恒计算出的IMAGE_NT_HEADER信息:\n\
Signature:%08X\n\n\
";
	sprintf(strTmp, strNTHeaderFormat, pNtH->Signature);
	printf("%s", strTmp);
	memset(strTmp, 0, sizeof(strTmp));




	pFH = GetFileHeader(pstMapFile->ImageBase);
	if (!pFH)
	{
		printf("毛月恒提醒：获取File头失败!\n");
		return;
	}
	//将信息按十六进制格式化
	char* strFileHeaderFormat = "\
毛月恒计算出的IMAGE_FILE_HEADER信息:\n\
Machine:%04X\n\
NumberOfSections:%04X\n\
Characteristics:%04X\n\n\
";
	sprintf(strTmp, strFileHeaderFormat, pFH->Machine, pFH->NumberOfSections, pFH->Characteristics);
	printf("%s", strTmp);
	memset(strTmp, 0, sizeof(strTmp));




	char* strFileOptHeaderFormat = "\
毛月恒计算出的IMAGE_OPTIONAL_HEADER信息:\n\
Magic:%04X\n\
SizeOfCode:%08X\n\
AddressOfEntryPoint:%08X\n\
ImageBase:%08X\n\
SectionAlignment:%08X\n\
FileAlignment:%08X\n\
SizeOfImage:%08X\n\n\
";
	pOH = GetOptionalHeader(pstMapFile->ImageBase);
	if (!pOH)
	{
		printf("毛月恒提醒：获取Optional头失败!\n");
		return;
	}
	sprintf(strTmp, strFileOptHeaderFormat, pOH->Magic, pOH->SizeOfCode, pOH->AddressOfEntryPoint, pOH->ImageBase, pOH->SectionAlignment, pOH->FileAlignment, pOH->SizeOfImage);
	printf("%s", strTmp);
	memset(strTmp, 0, sizeof(strTmp));


	pSH = GetSectionHeader(pstMapFile->ImageBase);
	for (i = 0; i < pFH->NumberOfSections; i++)
	{
		pSH = GetSectionHeader(pstMapFile->ImageBase);
		pSH = (PIMAGE_SECTION_HEADER)((int)pSH + sizeof(IMAGE_SECTION_HEADER)*i);
		if (!pSH)
		{
			printf("毛月恒提醒：获取Section头失败!\n");
			return;
		}
		printf("毛月恒计算出的IMAGE_%s_HEADER信息:\n", pSH->Name);
		char* strSectionHeaderFormat = "\
Name:%08X\n\
VirtureAddress:%04X\n\
SizeOfRawData:%04X\n\
PointerToRawData:%04X\n\
PointerToRelocations:%04X\n\
PointerToLineNumbers:%04X\n\
NumberOfRelocations:%02X\n\
NumberOfLineNumbers:%02X\n\
Characteristics:%04X\n\n\
";
		sprintf(strTmp, strSectionHeaderFormat, pSH->Name, pSH->VirtualAddress, pSH->SizeOfRawData, pSH->PointerToRawData, pSH->PointerToRelocations, pSH->PointerToLinenumbers, pSH->NumberOfRelocations, pSH->NumberOfLinenumbers, pSH->Characteristics);
		printf("%s", strTmp);
		memset(strTmp, 0, sizeof(strTmp));

	}


}




int main()
{
	LPTSTR filePath = _T("E:\\LoadPE\\LordPE.EXE");
	UnLoadFile(&pstMapFile);
	if (!LoadFile(filePath, &pstMapFile))
	{
		printf("毛月恒提醒：加载文件失败，请检查文件路径及文件名是否正确。");
		return -1;
	}


	if (!IsPEFile(pstMapFile.ImageBase))
	{
		printf("毛月恒提醒：该文件不是PE文件。");
		UnLoadFile(&pstMapFile);
		return -1;
	}


	ShowRVAInfo(&pstMapFile);
	ShowHeaderInfo(&pstMapFile);

	UnLoadFile(&pstMapFile);
	return 0;

	
	return 0;
}
