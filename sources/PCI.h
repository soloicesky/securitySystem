#ifndef _PCI_H_
#define _PCI_H_

#define ANSIX9_9CBC			0
#define ANSIX9_19ECB			1

#define CHARFLOW					0
#define BYTEFLOW						1

#define  MAX_TMK_LEN			24	
#define MAX_WORKING_LEN		24
#define MAX_KEY_SETS			16
#define SESSIONKEY_LEN			8

typedef struct _key_group_
{
	unsigned char index;
	unsigned char TMK[MAX_TMK_LEN];
	unsigned char TMK_Len;
	unsigned char WK_Pin[MAX_TMK_LEN];
	unsigned char WK_Pin_Len;
	unsigned char WK_Des[MAX_TMK_LEN];
	unsigned char WK_Des_Len;
	unsigned char WK_Mac[MAX_TMK_LEN];
	unsigned char WK_Mac_Len;
}Key_Group;


typedef struct _key_arc_
{
	unsigned char sessionKey[SESSIONKEY_LEN];
	Key_Group keyGroups[MAX_KEY_SETS];
	unsigned char size;
}Key_Arc;


//extern Key_Arc keyArc;


#define ERR_PCI_CREATE_KEYFILE_FAILED			-8000
#define ERR_PCI_WRITE_KEYFILE_FAILED			-8001
#define ERR_PCI_READ_KEYFILE_FAILED				-8002
#define ERR_PCI_INVALID_TMK_FAILED				-8003
#define ERR_PCI_NO_KEYFILE_FOUND				-8004
#define ERR_PCI_NONE_BUFFER						-8005
#define ERR_PCI_INVALID_MODE					-8006
#define ERR_PCI_INVALID_MACFORMAT				-8007



#define xor(a, b)			((a) ^ (b))

#endif

