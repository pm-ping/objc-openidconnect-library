//
//  RSAPKCS1_5.m
//  Copyright (c) 2013 Paul Meyer. All rights reserved.
//

#import "RSAPKCS1_5.h"
#import "SHA.h"
#import <CommonCrypto/CommonDigest.h>

@implementation RSAPKCS1_5

uint32_t kSecPadding;
NSUInteger DigestLengthValue;

- (id)init
{
    self = [super init];
    
    if (self) {
        SignedData = nil;
        PublicCert = nil;
        [self setSHA_DigestLength:256]; // default to SHA256
    }
    
    return self;
}

- (id)initWithData:(NSData *)data
{
    self = [super init];
    
    if (self) {
        SignedData = data;
        PublicCert = nil;
        [self setSHA_DigestLength:256]; // default to SHA256
    }
    
    return self;
}

- (id)initWithData:(NSData *)data andCert:(SecKeyRef)cert
{
    self = [super init];
    
    if (self) {
        SignedData = data;
        PublicCert = cert;
        [self setSHA_DigestLength:256]; // default to SHA256
    }
    
    return self;
}

- (id)initWithData:(NSData *)data Cert:(SecKeyRef)cert andSHADigestLength:(NSUInteger)digestLength
{
    self = [super init];
    
    if (self) {
        SignedData = data;
        PublicCert = cert;
        [self setSHA_DigestLength:digestLength];
    }
    
    return self;
}

- (void)setSHA_DigestLength:(NSUInteger)Length
{
    // default to 256
    
    if (Length == 512) {
        SHA_DigestLength = CC_SHA512_DIGEST_LENGTH;
        kSecPadding = kSecPaddingPKCS1SHA512;
        DigestLengthValue = 512;
    } else if (Length == 384) {
        SHA_DigestLength = CC_SHA384_DIGEST_LENGTH;
        kSecPadding = kSecPaddingPKCS1SHA384;
        DigestLengthValue = 384;
    } else {
        SHA_DigestLength = CC_SHA256_DIGEST_LENGTH;
        kSecPadding = kSecPaddingPKCS1SHA256;
        DigestLengthValue = 256;
    }
}

-(NSUInteger)SHA_DigestLength
{
    return DigestLengthValue;
}

- (BOOL)verifySignature:(NSData *)signature
{
    OSStatus sanityCheck = noErr;
    NSData *dataDigest;

    SHA *Hasher = [[SHA alloc] initWithData:SignedData andDigestLength:DigestLengthValue];
    dataDigest = [Hasher getHashBytes];
    
    size_t blockSize = SecKeyGetBlockSize(PublicCert);
    
    sanityCheck = SecKeyRawVerify(PublicCert,
                                  kSecPadding,
                                  (const uint8_t *)[dataDigest bytes],
                                  SHA_DigestLength,
                                  (const uint8_t *)[signature bytes],
                                  blockSize
                                  );
    
    return (sanityCheck == noErr) ? YES : NO;
}

@end
