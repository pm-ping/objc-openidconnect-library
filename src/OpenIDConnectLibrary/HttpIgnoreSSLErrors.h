//
//  HttpIgnoreSSLErrors.h
//  Copyright (c) 2013 Ping Identity. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface HttpIgnoreSSLErrors : NSObject

@property(atomic, retain) NSCondition *downloaded;
@property(nonatomic, retain) NSData *dataDownloaded;
@property(nonatomic) NSInteger responseCode;

-(NSData *)getData;

@end
