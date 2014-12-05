//
//  HttpHelper.h
//  Copyright (c) 2013 Ping Identity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "HttpResponse.h"

@interface HttpHelper : NSObject

+(HttpResponse *)postToUrl:(NSString *)url withPostData:(NSString *)postData;
+(HttpResponse *)postToUrl:(NSString *)url withPostData:(NSString *)postData withContentType:(NSString *)contentType;
+(HttpResponse *)getUrl:(NSString *)url withAuthZHeader:(NSString *)authZHeader;

@end
