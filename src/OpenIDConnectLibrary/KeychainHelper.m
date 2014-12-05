//
//  KeychainHelper.m
//  Copyright (c) 2014 Ping Identity. All rights reserved.
//

#import "KeychainHelper.h"

@implementation KeychainHelper

+(void)deletePublicCertFromKeyChain:(NSDictionary *)keychainRef
{
    NSMutableDictionary *publicKey = [[NSMutableDictionary alloc] initWithDictionary:keychainRef];
    SecItemDelete((__bridge CFDictionaryRef)publicKey);
}

+(BOOL)checkKeyExistsInKeyChain:(NSString *)keychainID
{
    NSData *d_tag = [NSData dataWithBytes:[keychainID UTF8String] length:[keychainID length]];
    
    NSMutableDictionary *publicKey = [[NSMutableDictionary alloc] init];
    [publicKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKey setObject:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
    [publicKey setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id)kSecAttrKeyClass];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [publicKey setObject:(__bridge id) kCFBooleanTrue forKey:(__bridge id)kSecReturnAttributes];
    
    CFDictionaryRef keychainRef = NULL;
    OSStatus result = SecItemCopyMatching((__bridge CFDictionaryRef)publicKey, (CFTypeRef *)&keychainRef);
    
    if (result == errSecSuccess) {
        NSDictionary *keychainAttributes = (__bridge_transfer NSDictionary *)keychainRef;
        NSDate *lastMod = keychainAttributes[(__bridge id)kSecAttrModificationDate];
        
        NSTimeInterval interval = [[NSDate date] timeIntervalSinceDate:lastMod];
        
        if (interval > 43200) { // greater than 12 hours
            [self deletePublicCertFromKeyChain:publicKey];
            return NO;
        } else {
            return YES;
        }
    }
    
    return NO;
}

+(SecKeyRef)getPublicCertFromKeyChainByIssuer:(NSString *)keychainID
{
    
    // Lets check to see if the cert is in the keychain and is within the PF rollover time (12 hours)
    if ([self checkKeyExistsInKeyChain:keychainID]) {
        
        NSLog(@"Retrieving public certificate from keychain: %@", keychainID);
        
        NSData *d_tag = [NSData dataWithBytes:[keychainID UTF8String] length:[keychainID length]];
        NSMutableDictionary *publicKey = [[NSMutableDictionary alloc] init];
        [publicKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
        [publicKey setObject:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
        [publicKey setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id)kSecAttrKeyClass];
        [publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
        [publicKey setObject:(__bridge id) kCFBooleanTrue forKey:(__bridge id)kSecReturnRef];
        
        SecKeyRef keyRef;
        OSStatus secStatus = SecItemCopyMatching((__bridge CFDictionaryRef)publicKey, (CFTypeRef *)&keyRef);
        
        if (secStatus == noErr) {
            return keyRef;
        } else {
            return nil;
        }
        
    } else {
        return nil;
    }
    
}

+(BOOL)storePublicCertInKeyChain:(SecKeyRef)key keychainIdentifier:(NSString *)keychainID
{
    NSData *d_tag = [NSData dataWithBytes:[keychainID UTF8String] length:[keychainID length]];
    
    NSLog(@"Adding public certificate to keychain: %@", keychainID);
    
    NSMutableDictionary *publicKey = [[NSMutableDictionary alloc] init];
    [publicKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKey setObject:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
    [publicKey setObject:(__bridge id)key forKey:(__bridge id)kSecValueRef];
    [publicKey setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id)kSecAttrKeyClass];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnPersistentRef];
    
    CFTypeRef persistKey = nil;
    OSStatus secStatus = SecItemAdd((__bridge CFDictionaryRef)publicKey, &persistKey);
    
    if (persistKey != nil) CFRelease(persistKey);
    
    if (secStatus == noErr) {
        return YES;
    } else {
        return NO;
    }
}

@end
