# PE文件加密壳
## 使用方法
Visual Studio 2022 下 Release x86模式编译

生成的执行程序文件在主目录的bin文件夹下
## 加密壳
对PE文件的text段进行异或加密(0x99)

Usage: ./jiake.exe \<inputfile> \<outputfile>