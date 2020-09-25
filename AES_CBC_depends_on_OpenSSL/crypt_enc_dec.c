/*
AES-128-CBC
编译方法：gcc -lcrypto -lssl -o crypt_enc_dec crypt_enc_dec.c
运行方法：
加密：./crypt_enc_dec enc <input file> <output file> ，其中，<input file>是要加密的文件， <output file>是加密后的密文文件
解密：./crypt_enc_dec dec <input file> <output file> ，其中，<input file>是密文文件， <output file>是解密后的文件
*/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif


/**
 * Encrypt or decrypt, depending on flag 'should_encrypt'
 */
void crypt(int should_encrypt, FILE *ifp, FILE *ofp, unsigned char *ckey, unsigned char *ivec) 
{
	// fseek(ifp,0L,SEEK_END);  // 这一句是将文件指针fp移动到文件数据的最后一位上
	// int len = ftell(ifp);    // 获取当前文件指针到文件开头的长度大小
	// fseek(ifp,0,0); 
	// const unsigned BUFSIZE = len;   // 文件的总大小
	const unsigned BUFSIZE = 4096;   // 4096                                            定义BUFSIZE=4096
	unsigned char *read_buf = malloc(BUFSIZE);    // C语言中malloc是动态内存分配函数      定义一个指针变量read_buf，并申请BUFSIZE大小的存储空间
	unsigned char *cipher_buf;
	unsigned blocksize;
	int out_len;
	EVP_CIPHER_CTX ctx;

	EVP_CipherInit(&ctx, EVP_aes_128_cbc(), ckey, ivec, should_encrypt);
	blocksize = EVP_CIPHER_CTX_block_size(&ctx);
	//printf("blocksize: %d\n", blocksize);
	cipher_buf = malloc(BUFSIZE + blocksize);    // C语言中malloc是动态内存分配函数
	//printf("cipher_buf: %d\n", cipher_buf);

	while(1)
	{
		// Read in data in blocks until EOF. Update the ciphering with each read.
		int numRead = fread(read_buf, sizeof(unsigned char), BUFSIZE, ifp);
		// printf("%d\n", numRead);
		// EVP_CIPHER_CTX_set_padding(&ctx, 1);
		EVP_CipherUpdate(&ctx, cipher_buf, &out_len, read_buf, numRead);    //对称计算（加/解密）函数，它调用了EVP_EncryptUpdate 和EVP_DecryptUpdate函数。
		fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);
		if (numRead < BUFSIZE) { // EOF
			break;
		}
	}

	// Now cipher the final block and write it out.
	int err_flag = EVP_CipherFinal(&ctx, cipher_buf, &out_len);
	if (!err_flag)
	{
		printf("error EVP_CipherFinal\n");
	}
	fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);

	// Free memory
	free(cipher_buf);
	free(read_buf);
}

// 16进制字符串转字节字节数组
int hexstringtobyte(char *in, unsigned char *out) {
    int len = (int)strlen(in);
    char *str = (char *)malloc(len);
    memset(str, 0, len);
    memcpy(str, in, len);
    int i;
    for (i = 0; i < len; i+=2) {
        //小写转大写
        if(str[i] >= 'a' && str[i] <= 'f') str[i] = str[i] & ~0x20;
        if(str[i+1] >= 'a' && str[i] <= 'f') str[i+1] = str[i+1] & ~0x20;
        //处理第前4位
        if(str[i] >= 'A' && str[i] <= 'F')
            out[i/2] = (str[i]-'A'+10)<<4;
        else
            out[i/2] = (str[i] & ~0x30)<<4;
        //处理后4位, 并组合起来
        if(str[i+1] >= 'A' && str[i+1] <= 'F')
            out[i/2] |= (str[i+1]-'A'+10);
        else
            out[i/2] |= (str[i+1] & ~0x30);
    }
    free(str);
    return 0;
}

int main(int argc, char *argv[]) 
{
	// 秘钥在这边 改
	unsigned char ckey_hex[] = "3e6989278da9cd9f12d8c33fc36cb496";   // 这串是获取的原始的16进制秘钥
	unsigned char ckey[16] = {0};
	hexstringtobyte(ckey_hex, ckey);                                 // 将16进制的秘钥形式转为字节
    // iv在这边 改
	unsigned char ivec_hex[] = "4257637228761bce344283dc68267515";
	unsigned char ivec[16] = {0};
	hexstringtobyte(ivec_hex, ivec);

	FILE *fIN, *fOUT;

	//argv[0] for encrypt or decrypt
	//argv[1] for input file
	//argv[2] for output file
	if(argc <= 3)
	{
		fprintf(stderr, "Usage: %s <enc for encrypt or dec for decrypt> \
		 <input file> <output file>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	
	//encrypt file
	if(strcmp(argv[1], "enc") == 0)
	{
		fIN = fopen(argv[2], "rb"); //File to be encrypted; plain text
		fOUT = fopen(argv[3], "wb"); //File to be written; cipher text

		crypt(TRUE, fIN, fOUT, ckey, ivec);

		fclose(fIN);
		fclose(fOUT);
	}
	//Decrypt file
	else if(strcmp(argv[1], "dec") == 0)
	{
		fIN = fopen(argv[2], "rb"); //File to be read; cipher text
		fOUT = fopen(argv[3], "wb"); //File to be written; cipher text

		crypt(FALSE, fIN, fOUT, ckey, ivec);

		fclose(fIN);
		fclose(fOUT);
	}
	else
	{
		printf("error input in argv[1].(should be \"enc\" or \"dec\")\n");
	}
	return 0;
}
