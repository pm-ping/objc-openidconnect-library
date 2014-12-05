//
//  CertHelper.h
//  Copyright (c) 2013 Paul Meyer. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface CertHelper : NSObject

+(SecKeyRef)getPublicCertFromX509Data:(NSData *)certData;
+(SecKeyRef)getPublicCertUsingModulus:(NSData*)modulus exponent:(NSData*)exponent;

@end
