//
//  HttpResponse.h
//  Copyright (c) 2013 Ping Identity. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface HttpResponse : NSObject
{
    NSData *responseData;
    NSUInteger responseCode;
}

@property (nonatomic, retain) NSData *responseData;
@property (nonatomic) NSUInteger responseCode;

-(id) init;

@end
