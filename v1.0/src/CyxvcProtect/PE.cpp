#include "stdafx.h"
#include "PE.h"


CPE::CPE()
{
	InitValue();
}


CPE::~CPE()
{
}

//************************************************************
// 函数名称:	InitValue
// 函数说明:	初始化变量
// 作	者:	cyxvc
// 时	间:	2015/12/25
// 返 回	值:	void
//************************************************************
void CPE::InitValue()
{
	m_hFile				= NULL;
	m_pFileBuf			= NULL;
	m_pDosHeader		= NULL;
	m_pNtHeader			= NULL;
	m_pSecHeader		= NULL;
	m_dwFileSize		= 0;
	m_dwImageSize		= 0;
	m_dwImageBase		= 0;
	m_dwCodeBase		= 0;
	m_dwCodeSize		= 0;
	m_dwPEOEP			= 0;
	m_dwShellOEP		= 0;
	m_dwSizeOfHeader	= 0;
	m_dwSectionNum		= 0;
	m_dwFileAlign		= 0;
	m_dwMemAlign		= 0;
	m_PERelocDir		= { 0 };
	m_PEImportDir		= { 0 };
	m_IATSectionBase	= 0;
	m_IATSectionSize	= 0;
}

//************************************************************
// 函数名称:	InitPE
// 函数说明:	初始化PE，读取PE文件，保存PE信息
// 作	者:	cyxvc
// 时	间:	2015/12/25
// 参	数:	CString strFilePath
// 返 回	值:	BOOL
//************************************************************
BOOL CPE::InitPE(CString strFilePath)
{
	//打开文件
	if (OpenPEFile(strFilePath) == FALSE)
		return FALSE;

	//将PE以文件分布格式读取到内存
	m_dwFileSize = GetFileSize(m_hFile, NULL);
	m_pFileBuf = new BYTE[m_dwFileSize];
	DWORD ReadSize = 0;
	ReadFile(m_hFile, m_pFileBuf, m_dwFileSize, &ReadSize, NULL);	
	CloseHandle(m_hFile);
	m_hFile = NULL;

	//判断是否为PE文件
	if (IsPE() == FALSE)
		return FALSE;

	//将PE以内存分布格式读取到内存
	//修正没镜像大小没有对齐的情况
	m_dwImageSize = m_pNtHeader->OptionalHeader.SizeOfImage;
	m_dwMemAlign = m_pNtHeader->OptionalHeader.SectionAlignment;
	m_dwSizeOfHeader = m_pNtHeader->OptionalHeader.SizeOfHeaders;
	m_dwSectionNum = m_pNtHeader->FileHeader.NumberOfSections;

	if (m_dwImageSize % m_dwMemAlign)
		m_dwImageSize = (m_dwImageSize / m_dwMemAlign + 1) * m_dwMemAlign;
	LPBYTE pFileBuf_New = new BYTE[m_dwImageSize];
	memset(pFileBuf_New, 0, m_dwImageSize);
	//拷贝文件头
	memcpy_s(pFileBuf_New, m_dwSizeOfHeader, m_pFileBuf, m_dwSizeOfHeader);
	//拷贝区段
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(m_pNtHeader);
	for (DWORD i = 0; i < m_dwSectionNum; i++, pSectionHeader++)
	{
		memcpy_s(pFileBuf_New + pSectionHeader->VirtualAddress,
			pSectionHeader->SizeOfRawData,
			m_pFileBuf+pSectionHeader->PointerToRawData,
			pSectionHeader->SizeOfRawData);
	}
	delete[] m_pFileBuf;
	m_pFileBuf = pFileBuf_New;
	pFileBuf_New = NULL;

	//获取PE信息
	GetPEInfo();
	
	return TRUE;
}

//************************************************************
// 函数名称:	OpenPEFile
// 函数说明:	打开文件
// 作	者:	cyxvc
// 时	间:	2015/12/25
// 参	数:	CString strFilePath
// 返 回	值:	BOOL
//************************************************************
BOOL CPE::OpenPEFile(CString strFilePath)
{
	m_hFile = CreateFile(strFilePath,
		GENERIC_READ | GENERIC_WRITE, 0, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (m_hFile == INVALID_HANDLE_VALUE)
	{
		MessageBox(NULL, _T("加载文件失败！"), _T("提示"), MB_OK);
		m_hFile = NULL;
		return FALSE;
	}
	return TRUE;
}

//************************************************************
// 函数名称:	IsPE
// 函数说明:	判断是否为PE文件
// 作	者:	cyxvc
// 时	间:	2015/12/25
// 返 回	值:	BOOL
//************************************************************
BOOL CPE::IsPE()
{
	//判断是否为PE文件
	m_pDosHeader = (PIMAGE_DOS_HEADER)m_pFileBuf;
	if (m_pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		//不是PE
		MessageBox(NULL, _T("不是有效的PE文件！"), _T("提示"), MB_OK);
		delete[] m_pFileBuf;
		InitValue();
		return FALSE;
	}
	m_pNtHeader = (PIMAGE_NT_HEADERS)(m_pFileBuf + m_pDosHeader->e_lfanew);
	if (m_pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		//不是PE文件
		MessageBox(NULL, _T("不是有效的PE文件！"), _T("提示"), MB_OK);
		delete[] m_pFileBuf;
		InitValue();
		return FALSE;
	}
	return TRUE;
}

//************************************************************
// 函数名称:	GetPEInfo
// 函数说明:	获取PE信息
// 作	者:	cyxvc
// 时	间:	2015/12/25
// 返 回	值:	void
//************************************************************
void CPE::GetPEInfo()
{
	m_pDosHeader	= (PIMAGE_DOS_HEADER)m_pFileBuf;
	m_pNtHeader		= (PIMAGE_NT_HEADERS)(m_pFileBuf + m_pDosHeader->e_lfanew);

	m_dwFileAlign	= m_pNtHeader->OptionalHeader.FileAlignment;
	m_dwMemAlign	= m_pNtHeader->OptionalHeader.SectionAlignment;
	m_dwImageBase	= m_pNtHeader->OptionalHeader.ImageBase;
	m_dwPEOEP		= m_pNtHeader->OptionalHeader.AddressOfEntryPoint;
	m_dwCodeBase	= m_pNtHeader->OptionalHeader.BaseOfCode;
	m_dwCodeSize	= m_pNtHeader->OptionalHeader.SizeOfCode;
	m_dwSizeOfHeader= m_pNtHeader->OptionalHeader.SizeOfHeaders;
	m_dwSectionNum	= m_pNtHeader->FileHeader.NumberOfSections;
	m_pSecHeader	= IMAGE_FIRST_SECTION(m_pNtHeader);
	m_pNtHeader->OptionalHeader.SizeOfImage = m_dwImageSize;

	//保存重定位目录信息
	m_PERelocDir = 
		IMAGE_DATA_DIRECTORY(m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

	//保存IAT信息目录信息
	m_PEImportDir =
		IMAGE_DATA_DIRECTORY(m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);

	//获取IAT所在的区段的起始位置和大小
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(m_pNtHeader);
	for (DWORD i = 0; i < m_dwSectionNum; i++, pSectionHeader++)
	{
		if (m_PEImportDir.VirtualAddress >= pSectionHeader->VirtualAddress&&
			m_PEImportDir.VirtualAddress <= pSectionHeader[1].VirtualAddress)
		{
			//保存该区段的起始地址和大小
			m_IATSectionBase = pSectionHeader->VirtualAddress;
			m_IATSectionSize = pSectionHeader[1].VirtualAddress - pSectionHeader->VirtualAddress;
			break;
		}
	}
}

//************************************************************
// 函数名称:	XorCode
// 函数说明:	代码段加密
// 作	者:	cyxvc
// 时	间:	2015/12/25
// 参	数:	BYTE byXOR
// 返 回	值:	DWORD
//************************************************************
DWORD CPE::XorCode(BYTE byXOR)
{
	PBYTE pCodeBase = (PBYTE)((DWORD)m_pFileBuf + m_dwCodeBase);
	for (DWORD i = 0; i < m_dwCodeSize; i++)
	{
		pCodeBase[i] ^= i;
	}
	return m_dwCodeSize;
}

//************************************************************
// 函数名称:	SetShellReloc
// 函数说明:	设置Shell的重定位信息
// 作	者:	cyxvc
// 时	间:	2015/12/25
// 参	数:	LPBYTE pShellBuf
// 返 回	值:	BOOL
//************************************************************
BOOL CPE::SetShellReloc(LPBYTE pShellBuf, DWORD hShell)
{
	typedef struct _TYPEOFFSET
	{
		WORD offset : 12;			//偏移值
		WORD Type	: 4;			//重定位属性(方式)
	}TYPEOFFSET, *PTYPEOFFSET;

	//1.获取被加壳PE文件的重定位目录表指针信息
	PIMAGE_DATA_DIRECTORY pPERelocDir =
		&(m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	
	//2.获取Shell的重定位表指针信息
	PIMAGE_DOS_HEADER		pShellDosHeader = (PIMAGE_DOS_HEADER)pShellBuf;
	PIMAGE_NT_HEADERS		pShellNtHeader = (PIMAGE_NT_HEADERS)(pShellBuf + pShellDosHeader->e_lfanew);
	PIMAGE_DATA_DIRECTORY	pShellRelocDir =
		&(pShellNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	PIMAGE_BASE_RELOCATION	pShellReloc = 
		(PIMAGE_BASE_RELOCATION)((DWORD)pShellBuf + pShellRelocDir->VirtualAddress);
	
	//3.还原修复重定位信息
	//由于Shell.dll是通过LoadLibrary加载的，所以系统会对其进行一次重定位
	//我们需要把Shell.dll的重定位信息恢复到系统没加载前的样子，然后在写入被加壳文件的末尾
	PTYPEOFFSET pTypeOffset = (PTYPEOFFSET)(pShellReloc + 1);
	DWORD dwNumber = (pShellReloc->SizeOfBlock - 8) / 2;

	for (DWORD i = 0; i < dwNumber; i++)
	{
		if (*(PWORD)(&pTypeOffset[i]) == NULL)
			break;
		//RVA
		DWORD dwRVA =pTypeOffset[i].offset + pShellReloc->VirtualAddress;
		//FAR地址（LordPE中这样标注）
		//***新的重定位地址=重定位后的地址-加载时的镜像基址+新的镜像基址+代码基址(PE文件镜像大小)
		DWORD AddrOfNeedReloc =	*(PDWORD)((DWORD)pShellBuf + dwRVA);
		*(PDWORD)((DWORD)pShellBuf + dwRVA) 
			= AddrOfNeedReloc - pShellNtHeader->OptionalHeader.ImageBase + m_dwImageBase + m_dwImageSize;
	}
	//3.1修改Shell重定位表中.text的RVA
	pShellReloc->VirtualAddress += m_dwImageSize;

	//4.修改PE重定位目录指针，指向Shell的重定位表信息
	pPERelocDir->Size = pShellRelocDir->Size;
	pPERelocDir->VirtualAddress = pShellRelocDir->VirtualAddress + m_dwImageSize;

	return TRUE;
}

//************************************************************
// 函数名称:	MergeBuf
// 函数说明:	合并PE文件和Shell
// 作	者:	cyxvc
// 时	间:	2015/12/25
// 参	数:	LPBYTE pFileBuf
// 参	数:	DWORD pFileBufSize
// 参	数:	LPBYTE pShellBuf
// 参	数:	DWORD pShellBufSize
// 参	数:	LPBYTE & pFinalBuf
// 返 回	值:	void
//************************************************************
void CPE::MergeBuf(LPBYTE pFileBuf, DWORD pFileBufSize,
	LPBYTE pShellBuf, DWORD pShellBufSize, 
	LPBYTE& pFinalBuf, DWORD& pFinalBufSize)
{
	//获取最后一个区段的信息
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pFileBuf + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	PIMAGE_SECTION_HEADER pLastSection =
		&pSectionHeader[pNtHeader->FileHeader.NumberOfSections - 1];

	//1.修改区段数量
	pNtHeader->FileHeader.NumberOfSections += 1;

	//2.编辑区段表头结构体信息
	PIMAGE_SECTION_HEADER AddSectionHeader =
		&pSectionHeader[pNtHeader->FileHeader.NumberOfSections - 1];
	memcpy_s(AddSectionHeader->Name, 8, ".cyxvc", 7);

	//VOffset(1000对齐)
	DWORD dwTemp = 0;
	dwTemp = (pLastSection->Misc.VirtualSize / m_dwMemAlign) * m_dwMemAlign;
	if (pLastSection->Misc.VirtualSize % m_dwMemAlign)
	{
		dwTemp += 0x1000;
	}
	AddSectionHeader->VirtualAddress = pLastSection->VirtualAddress + dwTemp;

	//Vsize（实际添加的大小）
	AddSectionHeader->Misc.VirtualSize = pShellBufSize;

	//ROffset（旧文件的末尾）
	AddSectionHeader->PointerToRawData = pFileBufSize;

	//RSize(200对齐)
	dwTemp = (pShellBufSize / m_dwFileAlign) * m_dwFileAlign;
	if (pShellBufSize % m_dwFileAlign)
	{
		dwTemp += m_dwFileAlign;
	}
	AddSectionHeader->SizeOfRawData = dwTemp;

	//标志
	AddSectionHeader->Characteristics = 0XE0000040;

	//3.修改PE头文件大小属性，增加文件大小
	dwTemp = (pShellBufSize / m_dwMemAlign) * m_dwMemAlign;
	if (pShellBufSize % m_dwMemAlign)
	{
		dwTemp += m_dwMemAlign;
	}
	pNtHeader->OptionalHeader.SizeOfImage += dwTemp;


	//4.申请合并所需要的空间
	pFinalBuf = new BYTE[pFileBufSize + dwTemp];
	pFinalBufSize = pFileBufSize + dwTemp;
	memset(pFinalBuf, 0, pFileBufSize + dwTemp);
	memcpy_s(pFinalBuf, pFileBufSize, pFileBuf, pFileBufSize);
	memcpy_s(pFinalBuf + pFileBufSize, dwTemp, pShellBuf, dwTemp);
}

//************************************************************
// 函数名称:	SetNewOEP
// 函数说明:	修改新的OEP为Shell的Start函数
// 作	者:	cyxvc
// 时	间:	2015/12/25
// 参	数:	DWORD dwOEP
// 返 回	值:	void
//************************************************************
void CPE::SetNewOEP(DWORD dwShellOEP)
{
	m_dwShellOEP = dwShellOEP + m_dwImageSize;
	m_pNtHeader->OptionalHeader.AddressOfEntryPoint = m_dwShellOEP;
}





