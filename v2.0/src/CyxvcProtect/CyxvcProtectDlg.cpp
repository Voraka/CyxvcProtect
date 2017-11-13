
// CyxvcProtectDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "CyxvcProtect.h"
#include "CyxvcProtectDlg.h"
#include "afxdialogex.h"
#include <tchar.h>
#include "PACK.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

CCyxvcProtectDlg::CCyxvcProtectDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CCyxvcProtectDlg::IDD, pParent)
	, m_strFilePath(_T(""))
	, m_strMachineCode(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CCyxvcProtectDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT1, m_strFilePath);
	DDX_Text(pDX, IDC_EDIT2, m_strMachineCode);
	DDX_Control(pDX, IDC_EDIT2, m_EditControl);
}

BEGIN_MESSAGE_MAP(CCyxvcProtectDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CCyxvcProtectDlg::OnBnClicked_OpenFile)
	ON_BN_CLICKED(IDC_BUTTON2, &CCyxvcProtectDlg::OnBnClicked_Pack)
	ON_WM_DROPFILES()
	ON_BN_CLICKED(IDC_CHECK3, &CCyxvcProtectDlg::OnBnClickedCheck3)
END_MESSAGE_MAP()

BOOL CCyxvcProtectDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO:  在此添加额外的初始化代码

	m_bSelect[0] = FALSE;
	m_bSelect[1] = FALSE;
	m_bSelect[2] = FALSE;
	m_bSelect[3] = FALSE;
	m_bSelect[4] = FALSE;
	m_EditControl.EnableWindow(FALSE);
	memset(m_arrMachineCode, 0, 16);

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CCyxvcProtectDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	CDialogEx::OnSysCommand(nID, lParam);
}

void CCyxvcProtectDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

HCURSOR CCyxvcProtectDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


//************************************************************
// 函数名称:	OnBnClicked_OpenFile
// 函数说明:	打开文件按钮
// 作	者:	cyxvc
// 时	间:	2015/12/24
// 返 回	值:	void
//************************************************************
void CCyxvcProtectDlg::OnBnClicked_OpenFile()
{
	UpdateData(TRUE);
	CFileDialog dlg(TRUE, NULL, NULL, 
		OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT,
		(LPCTSTR)_TEXT("All Files (*.*)|*.*||"), NULL);
	if (dlg.DoModal() == IDOK)
		m_strFilePath = dlg.GetPathName();
	else
		return;
	UpdateData(FALSE);
}


//************************************************************
// 函数名称:	OnBnClicked_Pack
// 函数说明:	加壳按钮
// 作	者:	cyxvc
// 时	间:	2015/12/24
// 返 回	值:	void
//************************************************************
void CCyxvcProtectDlg::OnBnClicked_Pack()
{
	if (m_strFilePath.IsEmpty())
	{
		MessageBox(_T("请选择被加壳的文件！"), _T("提示"), MB_OK);
		return;
	}
		
	//获取加壳选项
	if (GetSelect() == FALSE)
		return;

	//开始加壳
	CPACK objPACK;
	if (objPACK.Pack(m_strFilePath, m_bSelect, m_arrMachineCode))
		MessageBox(_T("加壳成功！"), _T("提示"), MB_OK);
}


//************************************************************
// 函数名称:	OnDropFiles
// 函数说明:	文件拖拽响应函数
// 作	者:	cyxvc
// 时	间:	2015/12/30
// 参	数:	HDROP hDropInfo
// 返 回	值:	void
//************************************************************
void CCyxvcProtectDlg::OnDropFiles(HDROP hDropInfo)
{
	UpdateData(TRUE);
	TCHAR FileName[MAX_PATH];
	DragQueryFile(hDropInfo, 0, FileName, MAX_PATH*sizeof(TCHAR));
	m_strFilePath = FileName;
	UpdateData(FALSE);
	CDialogEx::OnDropFiles(hDropInfo);
}

//************************************************************
// 函数名称:	GetSelect
// 函数说明:	获取加壳选项
// 作	者:	cyxvc
// 时	间:	2015/12/30
// 返 回	值:	BOOL
//************************************************************
BOOL CCyxvcProtectDlg::GetSelect()
{
	//获取是否加密代码段
	m_bSelect[0] = ((CButton*)GetDlgItem(IDC_CHECK1))->GetCheck();

	//获取是否加密IAT
	m_bSelect[1] = ((CButton*)GetDlgItem(IDC_CHECK2))->GetCheck();

	//获取是否绑定机器码
	m_bSelect[2] = ((CButton*)GetDlgItem(IDC_CHECK3))->GetCheck();
	if (m_bSelect[2])
	{
		//判断机器码的长度
		UpdateData(TRUE);
		if (m_strMachineCode.GetLength() != 32)
		{
			MessageBox(_T("请输入32位机器码！"), _T("提示"), MB_OK);
			return FALSE;
		}
		//保存机器码到数组
		
		CString strTemp;
		for (DWORD i = 0; i < 16; i++)
		{
			strTemp = m_strMachineCode[i * 2];
			strTemp += m_strMachineCode[i * 2 + 1];
			m_arrMachineCode[i] = _tcstol(strTemp, NULL, 16);
			strTemp.Empty();
		}
		UpdateData(FALSE);
	}

	//获取是否加入反调试
	m_bSelect[3] = ((CButton*)GetDlgItem(IDC_CHECK4))->GetCheck();

	//获取是否弹出MessageBox
	m_bSelect[4] = ((CButton*)GetDlgItem(IDC_CHECK5))->GetCheck();

	return TRUE;
}


void CCyxvcProtectDlg::OnBnClickedCheck3()
{
	BOOL bIsSelect = ((CButton*)GetDlgItem(IDC_CHECK3))->GetCheck();
	if (bIsSelect)
	{
		m_EditControl.EnableWindow(TRUE);
	}
	else
	{
		UpdateData(TRUE);
		m_EditControl.EnableWindow(FALSE);
		m_strMachineCode.Empty();
		UpdateData(FALSE);
	}
	
}
