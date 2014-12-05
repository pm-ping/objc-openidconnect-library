//
//  KeychainHelper.h
//  Copyright (c) 2014 Ping Identity. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface KeychainHelper : NSObject

+(BOOL)checkKeyExistsInKeyChain:(NSString *)keychainID;
+(SecKeyRef)getPublicCertFromKeyChainByIssuer:(NSString *)keychainID;
+(BOOL)storePublicCertInKeyChain:(SecKeyRef)key keychainIdentifier:(NSString *)keychainID;

@end
