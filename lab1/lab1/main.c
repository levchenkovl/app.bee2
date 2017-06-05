#pragma comment(lib, "bee2.lib")
#pragma comment(lib, "libbee2.lib")
#define _CRT_SECURE_NO_WARNINGS


#include "bee2/crypto/belt.h"
#include "stdio.h"
#ifdef OS_WIN
	#include <locale.h>
#endif

octet theta[32];
octet pwd[8];  
octet state[1024];
octet buf[64];
octet mac[8];
octet mac1[8];
octet iv[16];
size_t count;
size_t bufCount = sizeof(buf);




int help();

int main(int argc, char* argv[]) {


#ifdef OS_WIN
	setlocale(LC_ALL, "russian_belarus.1251");
#endif
	// Нет входных параметров
	if (argc < 2) 
		return help();

	// Вывод справки
	if (argc == 2 && strCmp(argv[1], "-h") == 0)
		return help();

	//параметры для шифрования
	if (argc == 8 && strCmp(argv[1], "-e") == 0 &&
		strCmp(argv[2], "-fin") == 0 &&
		strCmp(argv[4], "-fout") == 0 &&
		strCmp(argv[6], "-p") == 0) {

	//генерация синхропосылки
		char p[16];
		char a[] = "abcdefghijklmonpqrstuvwxyz1234568709йфячыцувсмакепитрнгоьблшщдюзжхэъ";
		for (int i = 0;i < 16;i++)
			p[i] = a[rand() % 48];
		memCopy(iv, p, 16);
			
		FILE* fpin = fopen(argv[3], "rb");
		FILE* fpout = fopen(argv[5], "wb");
		
	//размер файла	
		long nFileLen = 0;
		if (fpin)
		{
			fseek(fpin, 0, SEEK_END);
			nFileLen = ftell(fpin);
			fclose(fpin);
		}
		fpin = fopen(argv[3], "rb");

	//запись синхропосылки
		fwrite(iv, 1, 16, fpout);
		
		memCopy(pwd, argv[7], strLen(argv[7]));

	//построение ключа по паролю	
		beltPBKDF(theta, (const octet*)pwd, strLen((const char*)pwd), 10000, iv, 16);
		beltDWPStart(state, theta, 32, iv);
		beltDWPStepG(mac, state);

		while (nFileLen >= 0)
		{
			if (nFileLen < 64) {
				bufCount = nFileLen;
			};
			count = fread(buf, 1, bufCount, fpin);
			if (count == 0)
			{
				if (ferror(fpin))
				{
					fclose(fpin);
					fclose(fpout);
					printf("%s: FAILED [read]\n", argv[3]);
					return -1;
				}
				break;
			}


			nFileLen -= 64;
			beltDWPStepE(buf, bufCount, state);
			fwrite(buf, 1, bufCount, fpout);
		}

		

	//запись имитовставки
		fwrite(mac, 1, 8, fpout);
		fclose(fpin);
		fclose(fpout);
	} else
	if (argc == 8 && strCmp(argv[1], "-d") == 0 &&
		strCmp(argv[2], "-fin") == 0 &&
		strCmp(argv[4], "-fout") == 0 &&
		strCmp(argv[6], "-p") == 0) {

		//memCopy(pwd, argv[7], strLen(argv[7]));

		FILE* fpin = fopen(argv[3], "rb");
		FILE* fpout = fopen(argv[5], "wb");
		//размер файла	
		long nFileLen = 0;
		if (fpin)
		{
			fseek(fpin, 0, SEEK_END);
			nFileLen = ftell(fpin);
			fclose(fpin);
		}
		fpin = fopen(argv[3], "rb");
		
		fseek(fpin, nFileLen-8, SEEK_SET);
		fread(mac1, 1, 8, fpin);

		rewind(fpin);
		fread(iv, 1, 16, fpin);
		
	//построение ключа по паролю	
		beltPBKDF(theta, (const octet*)argv[7], strLen((const char*)argv[7]), 10000, iv, 16);
		beltDWPStart(state, theta, 32, iv);
		beltDWPStepG(mac, state);

		if (strCmp(mac, mac1) != 0) {
			printf("Failed\n");
			fclose(fpin);
			fclose(fpout);
			return 0;
		}

		nFileLen -= 24;
		while (nFileLen > 0)
		{
			if (nFileLen < 64) {
				bufCount = nFileLen;
			};
			count = fread(buf, 1, bufCount, fpin);
			if (count == 0)
			{
				if (ferror(fpin))
				{
					fclose(fpin);
					fclose(fpout);
					printf("%s: FAILED [read]\n", argv[3]);
					return -1;
				}
				break;
			}
			nFileLen -= 64;
			beltDWPStepD(buf, bufCount, state);

			fwrite(buf, 1, bufCount, fpout);
		}
		
		fclose(fpin);
		fclose(fpout);
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
