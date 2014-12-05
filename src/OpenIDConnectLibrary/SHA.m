//
//  SHA.m
//  Copyright (c) 2013 Paul Meyer. All rights reserved.
//

#import "SHA.h"
#import <CommonCrypto/CommonDigest.h>

@implementation SHA

@synthesize DataToHash = _DataToHash;
@synthesize DigestLength = _DigestLength;

int _CC_SHA_DIGEST_LENGTH;
uint32_t _HMACAlgorithm;

- (id)init
{
    self = [super init];
    
    if (self) {
        _DataToHash = nil;
        [self setDigestLength:256]; // default to SHA256
    }
    
    return self;
}


- (id)initWithData:(NSData *)data andDigestLength:(NSUInteger)length
{
    self = [super init];
    
    if (self) {
        _DataToHash = data;
        [self setDigestLength:length];
    }
    
    return self;
}

- (void)setDigestLength:(NSUInteger)Length
{
    // default to 256
    
    if (Length == 512) {
        _CC_SHA_DIGEST_LENGTH = CC_SHA512_DIGEST_LENGTH;
        _DigestLength = 512;
    }else if (Length == 384) {
        _CC_SHA_DIGEST_LENGTH = CC_SHA384_DIGEST_LENGTH;
        _DigestLength = 384;
    }else {
        _CC_SHA_DIGEST_LENGTH = CC_SHA256_DIGEST_LENGTH;
        _DigestLength = 256;
    }
}

- (NSUInteger)DigestLength
{
    return _DigestLength;
}

- (NSData *)getHashBytes
{
    if (_DigestLength == 512) {
        return [self getHashBytes256:_DataToHash];
    } else if (_DigestLength == 384) {
        return [self getHashBytes384:_DataToHash];
    } else {
        return [self getHashBytes256:_DataToHash];
    }
}

- (NSData *)getHashBytes256:(NSData *)plainText {
    CC_SHA256_CTX ctx;
    uint8_t * hashBytes = NULL;
    NSData * hash = nil;
    
    // Malloc a buffer to hold hash.
    hashBytes = malloc( CC_SHA256_DIGEST_LENGTH * sizeof(uint8_t) );
    memset((void *)hashBytes, 0x0, CC_SHA256_DIGEST_LENGTH);
    
    // Initialize the context.
    CC_SHA256_Init(&ctx);
    // Perform the hash.
    CC_SHA256_Update(&ctx, (void *)[plainText bytes], (unsigned int)[plainText length]);
    // Finalize the output.
    CC_SHA256_Final(hashBytes, &ctx);
    
    // Build up the SHA1 blob.
    hash = [NSData dataWithBytes:(const void *)hashBytes length:(NSUInteger)CC_SHA256_DIGEST_LENGTH];
    
    if (hashBytes) free(hashBytes);
    
    return hash;
}

- (NSData *)getHashBytes384:(NSData *)plainText {
    CC_SHA512_CTX ctx;
    uint8_t * hashBytes = NULL;
    NSData * hash = nil;
    
    // Malloc a buffer to hold hash.
    hashBytes = malloc( CC_SHA384_DIGEST_LENGTH * sizeof(uint8_t) );
    memset((void *)hashBytes, 0x0, CC_SHA384_DIGEST_LENGTH);
    
    // Initialize the context.
    CC_SHA384_Init(&ctx);
    // Perform the hash.
    CC_SHA384_Update(&ctx, (void *)[plainText bytes], (unsigned int)[plainText length]);
    // Finalize the output.
    CC_SHA384_Final(hashBytes, &ctx);
    
    // Build up the SHA1 blob.
    hash = [NSData dataWithBytes:(const void *)hashBytes length:(NSUInteger)CC_SHA384_DIGEST_LENGTH];
    
    if (hashBytes) free(hashBytes);
    
    return hash;
}

- (NSData *)getHashBytes512:(NSData *)plainText {
    CC_SHA512_CTX ctx;
    uint8_t * hashBytes = NULL;
    NSData * hash = nil;
    
    // Malloc a buffer to hold hash.
    hashBytes = malloc( CC_SHA512_DIGEST_LENGTH * sizeof(uint8_t) );
    memset((void *)hashBytes, 0x0, CC_SHA512_DIGEST_LENGTH);
    
    // Initialize the context.
    CC_SHA512_Init(&ctx);
    // Perform the hash.
    CC_SHA512_Update(&ctx, (void *)[plainText bytes], (unsigned int)[plainText length]);
    // Finalize the output.
    CC_SHA512_Final(hashBytes, &ctx);
    
    // Build up the SHA1 blob.
    hash = [NSData dataWithBytes:(const void *)hashBytes length:(NSUInteger)CC_SHA512_DIGEST_LENGTH];
    
    if (hashBytes) free(hashBytes);
    
    return hash;
}

@end
