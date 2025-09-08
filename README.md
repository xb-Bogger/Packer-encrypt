# GPU PACKER
## Introduction
Compared to the previous version, the new version v2.0 uses GPU to execute encryption routines. Using the OpenCL library to complete this work may cause a decrease in the speed of unpacking, but it can provide a new idea, which helps to introduce concurrent computing and avoid virtual environment analysis such as sandbox.
## Encryption
The encryption method uses simple XOR encryption, which can be expanded to complex encryption methods such as AES.
## Compilation
The compilation environment is VS2022(Release x86)

Usage: ./jiake.exe \<inputfile> \<outputfile>
