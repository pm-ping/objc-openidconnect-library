//
//  Utils.h
//  Copyright (c) 2014 Paul Meyer. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface Utils : NSObject

+(NSString *)base64UrlEncodeData:(NSData *)data;
+(NSData *)base64UrlDecodeString:(NSString *)base64EncodedString;
+(NSString *)jsonPrettyPrint:(NSDictionary *)jsonDictionary;
+(NSString *)jsonPrettyPrint:(NSString *)jsonString base64Encoded:(BOOL)base64Encoded;

@end
