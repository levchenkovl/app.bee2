#pragma comment(lib, "bee2.lib")
#pragma comment(lib, "libbee2.lib")
#define _CRT_SECURE_NO_WARNINGS


#include "bee2/crypto/belt.h"
#include "stdio.h"


octet theta[32];
octet pwd[8];  
octet state[1024];
octet buf[65536];
octet mac[8];
octet iv[16];



int help();

int main(int argc, char* argv[]) {
	// Нет входных параметров
	if (argc < 2) 
		return help();

	// Вывод справки
	if (argc == 2 && strCmp(argv[1], "-h") == 0)
		return help();

	//параметры для шифрования
	if (argc == 6 && strCmp(argv[1], "-e") == 0 &&
		strCmp(argv[2], "-f") == 0 &&
		strCmp(argv[4], "-p") == 0) {

	//генерация синхропосылки
		char p[16];
		char a[] = "abcdefghijklmonpqrstuvwxyz1234568709йфячыцувсмакепитрнгоьблшщдюзжхэъ";
		for (int i = 0;i < 16;i++)
			p[i] = a[rand() % 48];
		memCopy(iv, p, 16);
			
		FILE* fp = fopen(argv[3], "rb");
		
	//размер файла	
		long nFileLen = 0;
		if (fp)
		{
			fseek(fp, 0, SEEK_END);
			nFileLen = ftell(fp);
			fclose(fp);
		}
		fp = fopen(argv[3], "rb");
		fread(buf, 1, nFileLen, fp);
		fclose(fp);
		memCopy(pwd, argv[5], strLen(argv[5]));
		fp = fopen(argv[3], "wb");

	//запись синхропосылки
		fwrite(iv, 1, 16, fp);
		
	//построение ключа по паролю	
		beltPBKDF(theta, (const octet*)pwd, strLen((const char*)pwd), 10000, iv, 16);
		beltDWPStart(state, theta, 32, iv);
		beltDWPStepI(buf, nFileLen, state);

	//Шифруем
		beltDWPStepE(buf, nFileLen, state);
		beltDWPStepA(buf, nFileLen, state);
		beltDWPStepG(mac, state);
		beltDWPStepV(mac, state);

	//запись имитовставки
		fwrite(buf, 1, nFileLen, fp);
		fwrite(mac, 1, 8, fp);
		fclose(fp);
	} else
	if (argc == 6 && strCmp(argv[1], "-d") == 0 &&
		strCmp(argv[2], "-f") == 0 &&
		strCmp(argv[4], "-p") == 0) {

		FILE* fp = fopen(argv[3], "rb");
		
	//размер файла	
		long nFileLen = 0;
		if (fp)
		{
			fseek(fp, 0, SEEK_END);
			nFileLen = ftell(fp);
			fclose(fp);
		}
		long bufLen = nFileLen -24;
		fp = fopen(argv[3], "rb");
		fread(iv, 1, 16, fp);
		memCopy(pwd, argv[5], strLen(argv[5]));
		fread(buf, 1, bufLen, fp);
		
	//построение ключа по паролю	
		beltPBKDF(theta, (const octet*)pwd, strLen((const char*)pwd), 10000,iv, 16);
		beltDWPStart(state, theta, 32, iv);

	//расшифровываем
		beltDWPStepD(buf, bufLen, state); 
		fclose(fp);
		fp = fopen(argv[3], " wb");
		fwrite(buf, 1, bufLen, fp);
		fclose(fp);
	}
	else { return help(); }
	return 0;
	
}


//справка
int help() {
	printf(
		"------------------------------------------------------------------------------------------------------\n"
		"	lab1.exe  -e -f <file> -p <password>                   encrypt \n"
		"	lab1.exe  -d -f <file> -p <password>                   decrypt \n"
		"	lab1.exe  -h											help\n"
		"------------------------------------------------------------------------------------------------------\n"
	);
	return 0;
}
