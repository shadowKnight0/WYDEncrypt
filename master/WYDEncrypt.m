//
//  main.m
//  3DES研究
//
//  Created by apple on 15/10/22.
//  Copyright © 2015年 apple. All rights reserved.
//
#import <Foundation/Foundation.h>
#import "WYDEncrypt.h"
#import <CommonCrypto/CommonDigest.h>  
#import <CommonCrypto/CommonCryptor.h>
#import <Security/Security.h>




@implementation WYDEncrypt


+ (NSString *)threeDESEncrypt:(NSString *)plainText withKey:(NSString *)key{
    //16进制字符串转为 data数据
    NSData  *data = [self hexToBytes:key];
    
    //组装解密key取前16个字节然后再次取前8个字节组成key
    uint8_t *git = (uint8_t *)[data bytes];
    uint8_t keyByte[24];
    for (int i=0; i<16; i++) {
        keyByte[i] = git[i];
    }
    for (int i=0; i<8; i++) {
        keyByte[16+i] = git[i];
    }
    
    NSData *EncryptData = [self hexToBytes:plainText];
    
    size_t plainTextBufferSize = [EncryptData length];
    
    const void *vplainText = [EncryptData bytes];
    
    CCCryptorStatus ccStatus;
    uint8_t *bufferPtr = NULL;
    size_t bufferPtrSize = 0;
    size_t movedBytes = 0;
    
    bufferPtrSize = (plainTextBufferSize +kCCBlockSize3DES) & ~(kCCBlockSize3DES -1);
    
    bufferPtr =malloc(bufferPtrSize * sizeof(uint8_t));
    
    memset((void *)bufferPtr,0x0, bufferPtrSize);
    
    const void *vkey = (const void *) keyByte;
    
    ccStatus =CCCrypt(kCCEncrypt,
                      
                      kCCAlgorithm3DES,
                      
                      kCCOptionECBMode,
                      
                      vkey,
                      
                      kCCKeySize3DES,
                      
                      nil,                 //偏移量 直接传nil 不能传@“”
                      
                      vplainText,
                      
                      plainTextBufferSize,
                      
                      (void *)bufferPtr,
                      
                      bufferPtrSize,
                      
                      &movedBytes);
    
    NSData *dataresult = [NSData dataWithBytes:(const void *)bufferPtr
                          
                                       length:(NSUInteger)movedBytes];
    
    
    NSString *result = [self hexStringFromData:dataresult];
    
    return [result uppercaseString];
}

+ (NSString *)threeDESDecrypt:(NSString *)plainText withKey:(NSString *)key{
    //16进制字符串转为 data数据
    NSData  *data = [self hexToBytes:key];
    
    //组装解密key取前16个字节然后再次取前8个字节组成key
    uint8_t *git = (uint8_t *)[data bytes];
    uint8_t keyByte[24];
    for (int i=0; i<16; i++) {
        keyByte[i] = git[i];
    }
    for (int i=0; i<8; i++) {
        keyByte[16+i] = git[i];
    }
    
    NSData *EncryptData = [self hexToBytes:plainText];
    
    size_t plainTextBufferSize = [EncryptData length];
    
    const void *vplainText = [EncryptData bytes];
    
    CCCryptorStatus ccStatus;
    uint8_t *bufferPtr = NULL;
    size_t bufferPtrSize = 0;
    size_t movedBytes = 0;
    
    bufferPtrSize = (plainTextBufferSize +kCCBlockSize3DES) & ~(kCCBlockSize3DES -1);
    
    bufferPtr =malloc(bufferPtrSize * sizeof(uint8_t));
    
    memset((void *)bufferPtr,0x0, bufferPtrSize);
    
    const void *vkey = (const void *) keyByte;
    
    ccStatus =CCCrypt(kCCDecrypt,
                      
                      kCCAlgorithm3DES,
                      
                      kCCOptionECBMode,
                      
                      vkey,
                      
                      kCCKeySize3DES,
                      
                      nil,
                      
                      vplainText,
                      
                      plainTextBufferSize,
                      
                      (void *)bufferPtr,
                      
                      bufferPtrSize,
                      
                      &movedBytes);
    
    NSData *dataresult = [NSData dataWithBytes:(const void *)bufferPtr
                          
                                        length:(NSUInteger)movedBytes];
    
    
    NSString *result = [self hexStringFromData:dataresult];
    
    return [result uppercaseString];
}

//其中用到的两个方法如下

/**
 *  十六 进制字符串转换为 data
 *  24211D3498FF62AF  -->  <24211D34 98FF62AF>
 *
 *  @param str 要转换的字符串
 *
 *  @return 转换后的数据
 */

+(NSData*)hexToBytes:(NSString *)str{
    
    NSMutableData* data = [NSMutableData data];
    
    int idx;
    
    for (idx = 0; idx+2 <= str.length; idx+=2) {
        
        NSRange range = NSMakeRange(idx,2);
        
        NSString* hexStr = [str substringWithRange:range];
        
        NSScanner* scanner = [NSScanner scannerWithString:hexStr];
        
        unsigned int intValue;
        
        [scanner scanHexInt:&intValue];
        
        [data appendBytes:&intValue length:1];
        
    }
    
    return data;
}

/**
 *  data 转换为十六进制字符串
 *  <24211D34 98FF62AF>  -->  24211D3498FF62AF
 *
 *  @param data 要转换的data
 *
 *  @return 转换后的字符串
 */
+ (NSString *)hexStringFromData:(NSData *)data{
    
    NSMutableString *str = [NSMutableString string];
    
    Byte *byte = (Byte *)[data bytes];
    
    for (int i =0; i<[data length]; i++) {
        
        // byte+i为指针
        
        [str appendString:[self stringFromByte:*(byte+i)]];
        
    }
    
    return str;
    
}
+ (NSString *)stringFromByte:(Byte)byteVal

{
    NSMutableString *str = [NSMutableString string];
    //取高四位
    Byte byte1 = byteVal>>4;
    //取低四位
    Byte byte2 = byteVal & 0xf;
    //拼接16进制字符串
    [str appendFormat:@"%x",byte1];
    [str appendFormat:@"%x",byte2];
    return str;
    
}

@end
