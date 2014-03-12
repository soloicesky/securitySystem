#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "PCI.h"
#include "des.h"
#include "Utils.h"

#define KEY_FILE		"keyfile"

static Key_Arc keyArc;
static FILE *keyFp;

int XOR(unsigned char *inputBlock1, unsigned char *inputBlock2, unsigned char *result, int len);

static int existFile(char *fileName)
{
	FILE *fp = NULL;
	
	if(fileName == NULL)
	{
		return 0;
	}

	fp = fopen(fileName, "r");

	if(fp == NULL)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}


static int updateKeyArc(void)
{
	size_t size = 0;
	
	size = fwrite(&keyArc, sizeof(keyArc), 1, keyFp);
	
	if(size != sizeof(keyArc))
	{
		return ERR_PCI_WRITE_KEYFILE_FAILED;
	}

	return 0;
}


static int getKeyArc(void)
{
	size_t size = 0;
	size = fread(&keyArc, sizeof(keyArc), 1, keyFp);
	
	if(size != sizeof(keyArc))
	{
		return ERR_PCI_READ_KEYFILE_FAILED;
	}

	return 0;
}

int Init_keySystem(void)
{
	unsigned char IV = 0x74;
	int i = 0;

	keyFp = fopen(KEY_FILE, "wb+");

	if(keyFp == NULL)
	{
		return ERR_PCI_CREATE_KEYFILE_FAILED;
	}
	
	if(!existFile(KEY_FILE))
	{
		memset(&keyArc, 0x00, sizeof(keyArc));
		
		for(i = 0; i<SESSIONKEY_LEN; i++)
		{
			srand((int)time(NULL) + IV);
			IV = rand()%256;
			keyArc.sessionKey[i] = IV;
		}

		return  updateKeyArc();
	}
	else
	{
		return getKeyArc();
	}

}


int injectTMK(unsigned char tmkIndex, unsigned char *TMK, unsigned char tmkLen)
{	
	if(TMK == NULL || (tmkLen %8 != 0) ||(tmkLen /8 == 0) )
	{
		return ERR_PCI_INVALID_TMK_FAILED;
	}

	if(keyFp == NULL)
	{
		return ERR_PCI_NO_KEYFILE_FOUND;
	}

	keyArc.keyGroups[tmkIndex].TMK_Len = tmkLen;
	Des(TMK,tmkLen,keyArc.sessionKey,SESSIONKEY_LEN,keyArc.keyGroups[tmkIndex].TMK,DES_ENCRYPT,CBC);

	return updateKeyArc();
}


static int recoverTMK(unsigned char tmkIndex, unsigned char *plainTMK)
{	
	if(keyFp == NULL)
	{
		return ERR_PCI_NO_KEYFILE_FOUND;
	}

	if(plainTMK == NULL)
	{
		return ERR_PCI_NONE_BUFFER;
	}
	
	memset(plainTMK, 0x00, keyArc.keyGroups[tmkIndex].TMK_Len);
	Des(keyArc.keyGroups[tmkIndex].TMK,keyArc.keyGroups[tmkIndex].TMK_Len,
		keyArc.sessionKey,SESSIONKEY_LEN,plainTMK,DES_DECRYPT,CBC);
//	memcpy(keyArc.keyGroups.TMK, plainTMK, keyArc.keyGroups.TMK_Len);
	return 0;
}	

static int recoverPin_WK(unsigned char tmkIndex,  unsigned char *plainPinWk)
{	
	unsigned char plainTMK[MAX_WORKING_LEN];
	int ret = 0;
	
	if(keyFp == NULL)
	{
		return ERR_PCI_NO_KEYFILE_FOUND;
	}

	if(plainPinWk == NULL)
	{
		return ERR_PCI_NONE_BUFFER;
	}

	
	memset(plainTMK, 0x00, sizeof(plainTMK));
	ret = recoverTMK( tmkIndex, plainTMK);

	if(ret)
	{
		return ret;
	}
	
	memset(plainPinWk, 0x00, keyArc.keyGroups[tmkIndex].WK_Pin_Len);
	Des(keyArc.keyGroups[tmkIndex].WK_Pin,keyArc.keyGroups[tmkIndex].WK_Pin_Len,
		keyArc.keyGroups[tmkIndex].TMK,keyArc.keyGroups[tmkIndex].TMK_Len,
		plainPinWk,DES_DECRYPT,ECB);

	return 0;
}	


static int recoverDes_WK(unsigned char tmkIndex,  unsigned char *plainDesWk)
{	
	unsigned char plainTMK[MAX_WORKING_LEN];
	int ret = 0;
	
	if(keyFp == NULL)
	{
		return ERR_PCI_NO_KEYFILE_FOUND;
	}

	if(plainDesWk == NULL)
	{
		return ERR_PCI_NONE_BUFFER;
	}

	memset(plainTMK, 0x00, sizeof(plainTMK));
	ret = recoverTMK( tmkIndex, plainTMK);

	if(ret)
	{
		return ret;
	}

	memset(plainDesWk, 0x00, keyArc.keyGroups[tmkIndex].WK_Des_Len);
	Des(keyArc.keyGroups[tmkIndex].WK_Des,keyArc.keyGroups[tmkIndex].WK_Des_Len,
			keyArc.keyGroups[tmkIndex].TMK,keyArc.keyGroups[tmkIndex].TMK_Len,
			plainDesWk,DES_DECRYPT,ECB);

	return 0;
}	


static int recoverMac_WK(unsigned char tmkIndex,  unsigned char *plainMacWk)
{	
	unsigned char plainTMK[MAX_WORKING_LEN];
	int ret = 0;
	
	if(keyFp == NULL)
	{
		return ERR_PCI_NO_KEYFILE_FOUND;
	}

	if(plainMacWk == NULL)
	{
		return ERR_PCI_NONE_BUFFER;
	}

	memset(plainTMK, 0x00, sizeof(plainTMK));
	ret = recoverTMK( tmkIndex, plainTMK);

	if(ret)
	{
		return ret;
	}

	memset(plainMacWk, 0x00, keyArc.keyGroups[tmkIndex].WK_Mac_Len);
	Des(keyArc.keyGroups[tmkIndex].WK_Mac,keyArc.keyGroups[tmkIndex].WK_Mac_Len,
			keyArc.keyGroups[tmkIndex].TMK,keyArc.keyGroups[tmkIndex].TMK_Len,
			plainMacWk,DES_DECRYPT,ECB);

	return 0;
}	


int injectPinWK(unsigned char TMK_Index, unsigned char *pin_wk, unsigned char pin_wk_len)
{
	if(pin_wk == NULL || (pin_wk_len %8 != 0) ||(pin_wk_len /8 == 0) )
	{
		return ERR_PCI_INVALID_TMK_FAILED;
	}

	if(keyFp == NULL)
	{
		return ERR_PCI_NO_KEYFILE_FOUND;
	}

	keyArc.keyGroups[TMK_Index].WK_Pin_Len = pin_wk_len;
	memcpy(keyArc.keyGroups[TMK_Index].WK_Pin, pin_wk, pin_wk_len);

	return updateKeyArc();
}


int injectDesWK(unsigned char TMK_Index, unsigned char *des_wk, unsigned char des_wk_len)
{
	if(des_wk == NULL || (des_wk_len %8 != 0) ||(des_wk_len /8 == 0) )
	{
		return ERR_PCI_INVALID_TMK_FAILED;
	}

	if(keyFp == NULL)
	{
		return ERR_PCI_NO_KEYFILE_FOUND;
	}

	keyArc.keyGroups[TMK_Index].WK_Pin_Len = des_wk_len;
	memcpy(keyArc.keyGroups[TMK_Index].WK_Des, des_wk, des_wk_len);

	return updateKeyArc();
}


int injectMacWK(unsigned char TMK_Index, unsigned char *mac_wk, unsigned char mac_wk_len)
{
	if(mac_wk == NULL || (mac_wk_len %8 != 0) ||(mac_wk_len /8 == 0) )
	{
		return ERR_PCI_INVALID_TMK_FAILED;
	}

	if(keyFp == NULL)
	{
		return ERR_PCI_NO_KEYFILE_FOUND;
	}

	keyArc.keyGroups[TMK_Index].WK_Pin_Len = mac_wk_len;
	memcpy(keyArc.keyGroups[TMK_Index].WK_Mac, mac_wk, mac_wk_len);

	return updateKeyArc();
}

/*
int pci_genMac(unsigned char TMK_Index, unsigned char *msg, unsigned short msgLen, 
			unsigned char *mac, unsigned char *macLen, int algorithmType)
{
	if((msg == NULL) || (msgLen<=0) || (mac == NULL) || (macLen == NULL))
	{
		return ERR_PCI_NONE_BUFFER;
	}
}
*/

static int packPinFormat(unsigned char *formatedPin, char *plainPin)
{
	int i = 0;
	
	if( (formatedPin == NULL)  || (plainPin == NULL))
	{
		return ERR_PCI_NONE_BUFFER;
	}

	memset(formatedPin, 0xFF, 8);
	formatedPin[0] = strlen(plainPin);

	for(i = 0; i<strlen(plainPin); i++)
	{
		if(i%2)
		{
			formatedPin[i/2 +1] = (plainPin[i] - '0') <<  4;
		}
		else
		{
			formatedPin[i/2 +1] |= (plainPin[i] - '0');
		}
	}

	return 0;
}


int genFormatedPan(unsigned char *formatedPan, char *pan)
{
	int len = 0;
	char temPan[16];
	int offset = 0;
		
	if( (formatedPan == NULL)  || (pan == NULL))
	{
		return ERR_PCI_NONE_BUFFER;
	}

	offset = (strlen(pan)<=16)?0:(16 - (strlen(pan) - 1));
	memset(temPan, '0', sizeof(temPan));
	memcpy(temPan+offset, pan + (strlen(pan) - 1 -12), 12);
	return hexStringToByteArray(formatedPan,&len,temPan);
}


int pci_genPinBlock(unsigned char TMK_Index, char *pan,  char *plainPin,unsigned char *pinBlock)
{
	int ret = 0;
	unsigned char formatedPin[8];
	unsigned char formatedPan[8];
	unsigned char plaintextPinWK[MAX_WORKING_LEN];
	
	if( (pinBlock == NULL) ||(plainPin == NULL))
	{
		return ERR_PCI_NONE_BUFFER;
	}

	memset(formatedPin, 0x00, sizeof(formatedPin));
	ret = packPinFormat(formatedPin,  plainPin);

	if(ret)
	{
		return ret;
	}

	if(pan != NULL)
	{
		
		memset(formatedPan, 0x00, sizeof(formatedPan));
		ret = genFormatedPan(formatedPan, pan);

		if(ret)
		{
			return ret;
		}
			
		ret = XOR(formatedPin,formatedPan,formatedPin,8);

		if(ret)
		{
			return ret;
		}
	}

	memset(plaintextPinWK, 0x00, sizeof(plaintextPinWK));
	ret = recoverPin_WK(TMK_Index,plaintextPinWK);
	
	if(ret)
	{
		return ret;
	}
	
	Des(formatedPin,8,plaintextPinWK,keyArc.keyGroups[TMK_Index].WK_Pin_Len,
		pinBlock,DES_ENCRYPT,ECB);

	return 0;
}


int pci_Des(unsigned char TMK_Index, unsigned char *input, unsigned short inputLen, 
			unsigned char *output, unsigned char *outputLen, int algorithmType)
{
	unsigned char plainDesKey[MAX_WORKING_LEN];
	int ret = 0;
	
	if((input == NULL) || (inputLen<=0) || (output == NULL) || (outputLen == NULL))
	{
		return ERR_PCI_NONE_BUFFER;
	}

	memset(plainDesKey, 0x00, sizeof(plainDesKey));
	ret = recoverDes_WK(TMK_Index,plainDesKey);

	if(ret)
	{
		return ret;
	}
	
	Des( input, inputLen,plainDesKey,keyArc.keyGroups[TMK_Index].WK_Des_Len,
			output, DES_ENCRYPT, algorithmType);

	return 0;
}


int XOR(unsigned char *inputBlock1, unsigned char *inputBlock2, unsigned char *result, int len)
{
	int i = 0;

	if((inputBlock1 == NULL) || (inputBlock2 == NULL)|| (result == NULL))
	{
		return -1;
	}

	for(i=0; i<len; i++)
	{
		result[i] = xor(inputBlock1[i],inputBlock2[i]);
	}

	return 0;
}


static int genXorBlock(unsigned char *msg, unsigned short msgLen, unsigned char *output, int outputLen)
{
	int i = 0;
	unsigned char *tmb = NULL;
	int count = 0;
	int ret = 0;
	
	if((msg == NULL) || (output == NULL) || 
		(msgLen  <= 0) || (outputLen  <= 0))
	{
		return -1;
	}

	tmb = (unsigned char *)malloc(outputLen);

	if(tmb == NULL)
	{
		return -2;
	}

	count = (msgLen%outputLen)?((msgLen/outputLen)+1):(msgLen/outputLen);
	memset(output, 0x00, outputLen);

	for(i = 0; i<count; i++)
	{
		memset(tmb, 0x00, outputLen);
		
		if(( i==(count-1)) &&  (msgLen%outputLen))
		{
			memcpy(tmb, msg+i*outputLen,  (msgLen%outputLen));
		}
		else
		{
			memcpy(tmb, msg+i*outputLen,  outputLen);
		}

		ret = XOR(tmb, output,output, outputLen);

		if(ret)
		{
			return ret;
		}
	}

	return 0;
}



static int genMacANSIX9_19ECB(unsigned char tmkIndex,unsigned char *msg, unsigned short msgLen,
									unsigned char *MAC, int macLen)
{
	int ret = 0;
	unsigned char output[8];
	int outputLen = 8;
	unsigned char MBL[8];
	unsigned char MBR[8];
	int i = 0;
	unsigned char plainMacKey[MAX_WORKING_LEN];
	
	if((msg == NULL) || (output == NULL) || 
		(msgLen  <= 0) || (outputLen  <= 0))
	{
		return -1;
	}

	ret =  genXorBlock(msg, msgLen, output, outputLen);

	if(ret)
	{
		return ret;
	}

	memset(MBL, 0x00, sizeof(MBL));
	memset(MBR, 0x00, sizeof(MBR));

	for(i = 0; i<(outputLen/2); i++)
	{
		sprintf((char *)(MBL+i*2), "%02X", output[i]);
	}

	for(i = 0; i<(outputLen/2); i++)
	{
		sprintf((char *)(MBR+i*2), "%02X", output[4+i]);
	}

	ret = recoverMac_WK(tmkIndex,plainMacKey);
	
	if(ret)
	{
		return ret;
	}
	
	Des(MBL,8,plainMacKey,keyArc.keyGroups[tmkIndex].WK_Mac_Len,  output,DES_ENCRYPT,ECB);

	XOR(output, MBR, output, 8);

	Des(output,8,plainMacKey,keyArc.keyGroups[tmkIndex].WK_Mac_Len,  MAC,DES_ENCRYPT,ECB);

	return 0;
}


static int genMacANSIX9_9CBC(unsigned char tmkIndex,unsigned char *msg, unsigned short msgLen,
									unsigned char *MAC, int macLen)
{
	int ret = 0;
	unsigned char output[8];
	int outputLen = 8;
	unsigned char KEYL[8];
	unsigned char KEYR[8];
	int i = 0;
	unsigned char plainMacKey[MAX_WORKING_LEN];	
	int count = 0;
	unsigned char IV[8];
	
	if((msg == NULL) || (output == NULL) || 
		(msgLen  <= 0) || (outputLen  <= 0))
	{
		return -1;
	}

	memset(output, 0x00, sizeof(output));
	memset(KEYL, 0x00, sizeof(KEYL));
	memset(KEYL, 0x00, sizeof(KEYL));

	ret = recoverMac_WK(tmkIndex,plainMacKey);
	
	if(ret)
	{
		return ret;
	}

	memcpy(KEYL, plainMacKey, 8);
	memcpy(KEYR, plainMacKey+8, 8);
	count = (msgLen%outputLen)?((msgLen/outputLen)+1):(msgLen/outputLen);
	memset(IV, 0x00, sizeof(IV));

	for(i = 0; i<count; i++)
	{
		memset(output, 0x00, sizeof(output));
		
		if(( i==(count-1)) &&  (msgLen%outputLen))
		{
			memcpy(output, msg+i*outputLen,  (msgLen%outputLen));
		}
		else
		{
			memcpy(output, msg+i*outputLen,  outputLen);
		}

		ret = XOR(IV, output,IV,outputLen);
		
		if(ret)
		{
			return ret;
		}

		Des(IV,8,KEYL,8,  output,DES_ENCRYPT,ECB);
	}

	for(i=0; i<4;i++)
	{
		sprintf((char *)IV, "%02X", output[i]);
	}
	
	Des(IV,8,KEYR,8,  plainMacKey,DES_DECRYPT,ECB);

	for(i=0; i<4;i++)
	{
		sprintf((char *)IV, "%02X", output[i+4]);
	}

	XOR(IV, plainMacKey, output, 8);

	Des(output,8,KEYL,8,  MAC,DES_ENCRYPT,ECB);

	return 0;
}


int pci_GenMac(unsigned char tmkIndex,unsigned char *msg, unsigned short msgLen,
									unsigned char *MAC, int mode, int MACFormat)
{
	int ret = 0;
	unsigned char tempMac[8];
	int i = 0;

	memset(tempMac, 0x00, sizeof(tempMac));
	
	switch(mode)
	{
		case ANSIX9_9CBC:
			ret = genMacANSIX9_9CBC(tmkIndex, msg, msgLen,tempMac, 8);
			break;
		case ANSIX9_19ECB:
			ret = genMacANSIX9_19ECB(tmkIndex, msg, msgLen,tempMac, 8);
			break;

		default:
			return ERR_PCI_INVALID_MODE;
	}

	if(ret)
	{
		return ret;
	}

	switch(MACFormat)
	{
		case CHARFLOW:
			for(i = 0; i< 4; i++)
			{
				sprintf((char *)(MAC+i*2), "%02X", tempMac[i]);
			}
			break;
		case BYTEFLOW:
			memcpy(MAC, tempMac, 8);
			break;

		default:
			return ERR_PCI_INVALID_MACFORMAT;
	}

	return 0;
}

