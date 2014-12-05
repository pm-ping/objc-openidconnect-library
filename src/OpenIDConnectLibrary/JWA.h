//
//  JWA.h
//  Copyright (c) 2014 Ping Identity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "JWT.h"

@interface JWA : NSObject

typedef enum registeredAlgorithms {
    kJWAAlgorithmHMACwithSHA256 = 0,
    kJWAAlgorithmHMACwithSHA384,
    kJWAAlgorithmHMACwithSHA512,
    kJWAAlgorithmRSASSA_PKCS_v1_5withSHA256,
    kJWAAlgorithmRSASSA_PKCS_v1_5withSHA384,
    kJWAAlgorithmRSASSA_PKCS_v1_5withSHA512,
    kJWAAlgorithmECDSAwithP256andSHA256,
    kJWAAlgorithmECDSAwithP384andSHA384,
    kJWAAlgorithmECDSAwithP521andSHA512,
    kJWAAlgorithmRSASSA_PSS_withSHA256andMGF1withSHA256,
    kJWAAlgorithmRSASSA_PSS_withSHA384andMGF1withSHA384,
    kJWAAlgorithmRSASSA_PSS_withSHA512andMGF1withSHA512,
    kJWAAlgorithmNone
} JWAAlgorithm;

#define JWAAlgorithmArray @"HS256", @"HS384", @"HS512", @"RS256", @"RS384", @"RS512", @"ES256", @"ES384", @"ES512", @"PS256", @"PS384", @"PS512", @"none", nil

+(JWAAlgorithm)getAlgorithmType:(JWT *)jwt;

@end
