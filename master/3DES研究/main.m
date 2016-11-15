//
//  main.m
//  3DES研究
//
//  Copyright © 2016年 apple. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "WYDEncrypt.h"



int main(int argc, const char * argv[]) {
    @autoreleasepool {
      
        NSString *a = [WYDEncrypt threeDESEncrypt:@"61D1602101100064" withKey:@"B689FD09A1B241799DAD084E68A9F90B"];
         NSLog(@"字符串加密:%@",a);
        
        NSString *b = [WYDEncrypt threeDESDecrypt:a withKey:@"B689FD09A1B241799DAD084E68A9F90B"];
        NSLog(@"字符串解密:%@",b);
    }
    return 0;
}
