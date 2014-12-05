//
//  CertHelper.m
//  Copyright (c) 2013 Paul Meyer. All rights reserved.
//

#import "CertHelper.h"
#import "HttpHelper.h"
#import "Utils.h"
#import "KeychainHelper.h"

@implementation CertHelper

+(SecKeyRef)getPublicCertFromX509Data:(NSData *)certData {
    
    CFDataRef cfRef = CFDataCreate(NULL, [certData bytes], [certData length]);
    SecCertificateRef cert = SecCertificateCreateWithData(NULL, cfRef);
    SecKeyRef key = NULL;
    SecTrustRef trust = NULL;
    SecPolicyRef policy = NULL;
    
    if (cert != NULL) {
        policy = SecPolicyCreateBasicX509();
        if (policy) {
            if (SecTrustCreateWithCertificates((CFTypeRef)cert, policy, &trust) == noErr) {
                SecTrustResultType result;
                if (SecTrustEvaluate(trust, &result) == noErr) {
                    key = SecTrustCopyPublicKey(trust);
                }
            }
        }
    }
    if (policy) CFRelease(policy);
    if (trust) CFRelease(trust);
    if (cert) CFRelease(cert);
    return key;
}

+(NSUInteger) bytesInNSUInteger:(NSUInteger)nsuInteger
{
    NSUInteger bytes = 0;
    
    for (; nsuInteger; nsuInteger >>= 8)
    {
        bytes++;
    }
    
    return bytes;
}

+(NSUInteger) derEncodeDataLength:(NSUInteger)dataLength buffer:(Byte[])returnBuffer
{
    NSUInteger size = [self bytesInNSUInteger:dataLength];
    NSUInteger bigELength;
    BytePtr src;
    
#if __LP64__
    bigELength = (NSUInteger)NSSwapHostLongToBig(dataLength);
    src = (BytePtr)&bigELength + (8-size);
#else
    bigELength = (NSUInteger)NSSwapHostIntToBig(dataLength);
    src = (BytePtr)&bigELength + (4-size);
#endif
    
    BytePtr dst = &returnBuffer[0];
    if (*src & 0x80) {
        *dst++ = 0;
        size++;
    }
    memcpy(dst, src, size);
    return size;
}


+(NSMutableData *) derEncodeData:(NSData *)data tag:(size_t)tag
{
    NSMutableData *derData = [[NSMutableData alloc] init];
    
    size_t dataLength = [data length];
    UInt8 dataBuf[9];
    size_t dataSize = [self derEncodeDataLength:dataLength buffer:dataBuf];
    
    [derData appendBytes:&tag length:1];
    if (dataSize > 1)
    {
        size_t numBytes = 0x80 + dataSize;
        [derData appendBytes:&numBytes length:1];
    }
    [derData appendBytes:dataBuf length:dataSize];
    [derData appendBytes:data.bytes length:dataLength];
    
    return derData;
}

+(NSData *)derEncodePublicCertUsingModulus:(NSData *)modulus withExponent:(NSData *)exponent
{
    //    30 +
    //    length of entire packet -
    //    (if length > 127 (7F)) { 0x80 + num bytes of length, length in bytes }
    //    else { length in bytes }
    //    02 +
    //    length of modulus -
    //    (if length > 127 (7F)) { 0x80 (definitive form - long) + num bytes of length, length in bytes }
    //    else { length in bytes }
    //    modulus
    //    02 +
    //    length of exponent -
    //    (if length > 127 (7F)) { 0x80 (definitive form - long) + num bytes of length, length in bytes }
    //    else { length in bytes }
    //    exponent
    //
    //    DER Length =
    //    if length is > 127 (binary 11111111 not allowed so largest number is 01111111 (7F or 127dec))
    //      Binary 10000000 AND number of bytes for the length field
    //    else length < 128
    //      length of data in bytes
    
    Byte tagINTEGER = 0x02;
    Byte tagSEQUENCE = 0x30;
    
    NSMutableData *returnData = [[NSMutableData alloc] init];
    
    NSMutableData *modulusData = [self derEncodeData:modulus tag:tagINTEGER];
    NSMutableData *exponentData = [self derEncodeData:exponent tag:tagINTEGER];
    
    [returnData appendData:modulusData];
    [returnData appendData:exponentData];
    
    returnData = [self derEncodeData:returnData tag:tagSEQUENCE];
    
    return returnData;
}

+(SecKeyRef)getPublicCertUsingModulus:(NSData*)modulus exponent:(NSData*)exponent
{
    NSString *tag = @"Public Cert";
    NSData *d_tag = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];
    NSData *d_key = [self derEncodePublicCertUsingModulus:modulus withExponent:exponent];
    
    // Delete any old lingering key with the same tag
    NSMutableDictionary *publicKey = [[NSMutableDictionary alloc] init];
    [publicKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [publicKey setObject:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)publicKey);
    
    CFTypeRef persistKey = nil;
    
    // Add persistent version of the key to system keychain
    [publicKey setObject:d_key forKey:(__bridge id)kSecValueData];
    [publicKey setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id)kSecAttrKeyClass];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnPersistentRef];
    
    OSStatus secStatus = SecItemAdd((__bridge CFDictionaryRef)publicKey, &persistKey);
    
    if (persistKey != nil) CFRelease(persistKey);
    
    if ((secStatus != noErr) && (secStatus != errSecDuplicateItem)) {
        NSLog(@"SecItemAdd = %d", (int)secStatus);
        return nil;
    }
    
    // Now fetch the SecKeyRef version of the key
    SecKeyRef keyRef;
    
    [publicKey removeObjectForKey:(__bridge id)kSecValueData];
    [publicKey removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    [publicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    secStatus = SecItemCopyMatching((__bridge CFDictionaryRef)publicKey, (CFTypeRef *)&keyRef);
    
    if (secStatus != noErr) {
        NSLog(@"SecItemCopyMatching = %d", (int)secStatus);
        return nil;
    }
    
    return keyRef;
}

@end
