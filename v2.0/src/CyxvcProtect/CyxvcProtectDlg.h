
// CyxvcProtectDlg.h : 头文件
//

#pragma once
#include "afxwin.h"


// CCyxvcProtectDlg 对话框
class CCyxvcProtectDlg : public CDialogEx
{
// 构造
public:
	CCyxvcProtectDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_CYXVCPROTECT_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnBnClickedCheck3();
	afx_msg void OnDropFiles(HDROP hDropInfo);
	DECLARE_MESSAGE_MAP()
public:
	CString m_strFilePath;					//被加壳文件路径
	CString m_strMachineCode;					//机器码字符串
	CHAR m_arrMachineCode[16];					//机器码数组
	CEdit m_EditControl;					//机器码EditControl控件对象
	BOOL m_bSelect[5];						//加壳选项
	afx_msg void OnBnClicked_OpenFile();	//打开文件按钮
	afx_msg void OnBnClicked_Pack();		//加壳按钮
	BOOL GetSelect();						//获取加壳选项				
};
