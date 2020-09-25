AES加密解密  
ECB模式  
依赖于OpenSSL  
运行环境：Linux, CentOS7  
在Linux系统下编译之前要安装好openssl，gcc编译时要在-o之前加上 -lcrypto -lssl，例如：gcc AES_ECB.c -lcrypto -lssl -o AES_ECB  
  
说明：  
目前是将需要加密的TXT文件在main函数中指定好，那边也是可以加上文件的指定路径的  
目前实现的功能是将原文件中的加密得到密文并存储，然后再将密文解密得到解密后的文件，这样可以比较看出加密解密后的是否一样  