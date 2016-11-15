//
//  main.m
//  3DES研究
//
//  Copyright © 2016年 apple. All rights reserved.
//


#import <Foundation/Foundation.h>

@interface WYDEncrypt : NSObject


+ (NSString *)threeDESEncrypt:(NSString *)plainText withKey:(NSString *)key; //加密
+ (NSString *)threeDESDecrypt:(NSString *)plainText withKey:(NSString *)key; //解密

@end
