# app.bee2
Простое консольное приложение, зашифрование / расшифрование файлов на пароле.
По паролю строится ключ (beltPBKDF), на этом ключе выполняется зашифрование и имитозащита (beltDWP).
Зашифрованный файл сопровождается синхропосылкой (в начале) и имитовставкой (в конце).
"------------------------------------------------------------------------------------------------------\n"
"	lab1.exe  -e -f <file> -p <password>                   encrypt \n"
"	lab1.exe  -d -f <file> -p <password>                   decrypt \n"
"	lab1.exe  -h						help\n"
"------------------------------------------------------------------------------------------------------\n"