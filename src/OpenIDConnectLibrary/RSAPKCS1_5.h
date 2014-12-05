//
//  RSAPKCS1_5.h
//  Copyright (c) 2013 Paul Meyer. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface RSAPKCS1_5 : NSObject {
    
    NSData *SignedData;
    SecKeyRef PublicCert;
    NSUInteger SHA_DigestLength;
}

- (id)init;
- (id)initWithData:(NSData *)data;
- (id)initWithData:(NSData *)data andCert:(SecKeyRef)cert;
- (id)initWithData:(NSData *)data Cert:(SecKeyRef)cert andSHADigestLength:(NSUInteger)digestLength;
- (BOOL)verifySignature:(NSData *)signature;

@end
