//
//  HMAC.h
//  Copyright (c) 2013 Paul Meyer. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface HMAC : NSObject
{
    NSData *HashedData;
    NSData *SymmetricKey;
    NSUInteger SHA_DigestLength;
    
}

@property (nonatomic, retain) NSData *HashedData;
@property (nonatomic, retain) NSData *SymmetricKey;
@property NSUInteger SHA_DigestLength;

- (id)init;
- (id)initWithData:(NSData *)data;
- (id)initWithData:(NSData *)data andKey:(NSData *)key;
- (id)initWithData:(NSData *)data Key:(NSData *)key andSHADigestLength:(NSUInteger)digestLength;
- (BOOL)verifySignature:(NSData *)signature;

@end
