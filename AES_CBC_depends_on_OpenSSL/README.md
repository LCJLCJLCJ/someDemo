# AES加密解密   
## CBC模式   
依赖于OpenSSL    
运行环境：Linux, CentOS7   
在Linux系统下编译之前要安装好openssl，gcc编译时要在-o之前加上 -lcrypto -lssl   
加解密一体，通过参数`enc`和`dec`区分加密和解密
   
   
#### 编译方法：   
`gcc -lcrypto -lssl -o crypt crypt_enc_dec.c`
#### 运行方法：    
加密：`./crypt enc input.file output.file`    
	其中，input.file是要加密的文件， output.file是加密后的密文文件   
解密：`./crypt dec input.file output.file`    
	其中，input.file是密文文件， output.file是解密后的文件   
