#ifndef _USERTYPE_H_
#define _USERTYPE_H_

#ifdef __cplusplus
extern "C"
{
#endif

#define YES			(1)
#define NO			(0)

#define byte		unsigned char     //8bit �޷�����
#define tchar		char			  //8bit �޷�����

#define int16		short				//16bit �з�����
#define uint16		unsigned short		//16bit �޷�����
#define int32		int					//32bit �з�����
#define uint32		unsigned int		//32bit �޷�����
#define int64		long long				//64bit �з�����
#define uint64		unsigned long long	//64bit �޷�����
	
#define cstring	    tchar*				//�ַ���
#define byteArray	byte*				//8bit �޷�������

#define boolean	    byte				//����ֵ
#define true		(1)					//��
#define false		(0)					//��

typedef struct _dol_data_
{
	byteArray	value;
	uint16		len;
}DolData;

#ifdef __cplusplus
}
#endif

#endif

