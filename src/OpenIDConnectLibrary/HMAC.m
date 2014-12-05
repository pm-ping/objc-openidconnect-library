//
//  HMAC.m
//  Copyright (c) 2013 Paul Meyer. All rights reserved.
//

#import "HMAC.h"
#import <CommonCrypto/CommonHMAC.h>

@implementation HMAC

@synthesize HashedData = _HashedData;
@synthesize SymmetricKey = _SymmetricKey;
@synthesize SHA_DigestLength = _SHA_DigestLength;

int _CC_SHA_DIGEST_LENGTH;
uint32_t _HMACAlgorithm;

- (id)init
{
    self = [super init];
    
    if (self) {
        _HashedData = nil;
        _SymmetricKey = nil;
        [self setSHA_DigestLength:256]; // default to SHA256
    }
    
    return self;
}

- (id)initWithData:(NSData *)data
{
    self = [super init];
    
    if (self) {
        _HashedData = data;
        _SymmetricKey = nil;
        [self setSHA_DigestLength:256]; // default to SHA256
    }
    
    return self;
}

- (id)initWithData:(NSData *)data andKey:(NSData *)key
{
    self = [super init];
    
    if (self) {
        _HashedData = data;
        _SymmetricKey = key;
        [self setSHA_DigestLength:256]; // default to SHA256
    }
    
    return self;
}

- (id)initWithData:(NSData *)data Key:(NSData *)key andSHADigestLength:(NSUInteger)digestLength
{
    self = [super init];
    
    if (self) {
        _HashedData = data;
        _SymmetricKey = key;
        [self setSHA_DigestLength:digestLength];
    }
    
    return self;
}

- (void)setSHA_DigestLength:(NSUInteger)Length
{
    // default to 256
    
    if (Length == 512) {
        _CC_SHA_DIGEST_LENGTH = CC_SHA512_DIGEST_LENGTH;
        _HMACAlgorithm = kCCHmacAlgSHA512;
        _SHA_DigestLength = 512;
    }else if (Length == 384) {
        _CC_SHA_DIGEST_LENGTH = CC_SHA384_DIGEST_LENGTH;
        _HMACAlgorithm = kCCHmacAlgSHA384;
        _SHA_DigestLength = 384;
    }else {
        _CC_SHA_DIGEST_LENGTH = CC_SHA256_DIGEST_LENGTH;
        _HMACAlgorithm = kCCHmacAlgSHA256;
        _SHA_DigestLength = 256;
    }
    
}

- (NSUInteger)SHA_DigestLength
{
    return _SHA_DigestLength;
}

- (BOOL)verifySignature:(NSData *)signature
{
//    const char *cData = [_HashedData cStringUsingEncoding:NSASCIIStringEncoding];
//    const char *cKey = [_SymmetricKey cStringUsingEncoding:NSASCIIStringEncoding];
    
    unsigned char cHMAC[_CC_SHA_DIGEST_LENGTH];
    
    CCHmac(_HMACAlgorithm, [_SymmetricKey bytes], [_SymmetricKey length], [_HashedData bytes], [_HashedData length], cHMAC);
    NSData *hash = [[NSData alloc] initWithBytes:cHMAC length:sizeof(cHMAC)];
    
    return [hash isEqualToData:signature];
}

@end
