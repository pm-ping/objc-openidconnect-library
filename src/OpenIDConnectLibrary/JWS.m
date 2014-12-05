//
//  JWS.m
//  Copyright (c) 2014 Ping Identity. All rights reserved.
//

#import "JWS.h"
#import "JWA.h"
#import "JWKS.h"
#import "MetadataHelper.h"
#import "HttpHelper.h"

#import "HMAC.h"
#import "RSAPKCS1_5.h"

@implementation JWS

-(id)init {

    if (self = [super init]) {
        return self;
    }
    
    return nil;
}

-(id)initWithJWT:(JWT *)jwt {
    
    self = [self init];
    
    signingAlgorithm = [JWA getAlgorithmType:jwt];
    token = jwt;
    
    return self;
}

-(JWAAlgorithm)getAlgorithm {

    return signingAlgorithm;
}

+(JWT *)signJWT:(JWT *)jwt {
    
    //TODO: Support signing a JWT
    return nil;
}

+(JWT *)signJWTPayloadAsDictionary:(NSDictionary *)payload {
    
    //TODO: Support signing a JWT
    return nil;
}

+(JWT *)signJWTPayloadAsJSONString:(NSString *)payload {
    
    //TODO: Support signing a JWT
    return nil;
}

-(void)setSymmetricKey:(NSData *)key {

    symmetricKey = key;
}

-(void)setAsymmetricKeyRef:(SecKeyRef)key {
    
    asymmetricKeyRef = key;
}

-(BOOL)verifySignature {

    NSData *signedData = [[token getSignedData] dataUsingEncoding:NSUTF8StringEncoding];
    NSData *signature = [token getSignature];
    SecKeyRef keyRef = [self getKeyRef];
    
    switch (signingAlgorithm) {

        case kJWAAlgorithmHMACwithSHA256:
            return [self verifyHMACSignature:signature forData:signedData usingSymmetricKey:symmetricKey andSHAHashLength:256];
            break;
            
        case kJWAAlgorithmHMACwithSHA384:
            return [self verifyHMACSignature:signature forData:signedData usingSymmetricKey:symmetricKey andSHAHashLength:384];
            break;
            
        case kJWAAlgorithmHMACwithSHA512:
            return [self verifyHMACSignature:signature forData:signedData usingSymmetricKey:symmetricKey andSHAHashLength:512];
            break;
            
        case kJWAAlgorithmRSASSA_PKCS_v1_5withSHA256:
            return [self verifyRSAPKCS1_5Signature:signature forData:signedData usingKey:keyRef andSHAHashLength:256];
            break;
            
        case kJWAAlgorithmRSASSA_PKCS_v1_5withSHA384:
            return [self verifyRSAPKCS1_5Signature:signature forData:signedData usingKey:keyRef andSHAHashLength:384];
            break;
            
        case kJWAAlgorithmRSASSA_PKCS_v1_5withSHA512:
            return [self verifyRSAPKCS1_5Signature:signature forData:signedData usingKey:keyRef andSHAHashLength:512];
            break;
            
        case kJWAAlgorithmECDSAwithP256andSHA256:
            return NO; // Not supported
            break;
            
        case kJWAAlgorithmECDSAwithP384andSHA384:
            return NO; // Not supported
            break;
            
        case kJWAAlgorithmECDSAwithP521andSHA512:
            return NO; // Not supported
            break;
            
        case  kJWAAlgorithmRSASSA_PSS_withSHA256andMGF1withSHA256:
            return NO; // Not supported
            break;
            
        case kJWAAlgorithmRSASSA_PSS_withSHA384andMGF1withSHA384:
            return NO; // Not supported
            break;
            
        case kJWAAlgorithmRSASSA_PSS_withSHA512andMGF1withSHA512:
            return NO; // Not supported
            break;
            
        case kJWAAlgorithmNone:
            return YES;
            break;
            
        default:
            break;
            
    }
    
    
    //TODO: Grab a JWA with the key and signing method..
    //TODO: Build the signed data
    //TODO: Run the signed data against the JWA
    
    return YES;
}

#pragma mark Validation Methods

-(BOOL)verifyHMACSignature:(NSData *)signature forData:(NSData *)signedData usingSymmetricKey:(NSData *)key andSHAHashLength:(NSUInteger)SHALength {

    HMAC *hmacAlgorithm = [[HMAC alloc] initWithData:signedData andKey:key];
    [hmacAlgorithm setSHA_DigestLength:SHALength];
    return [hmacAlgorithm verifySignature:signature];
}

-(BOOL)verifyRSAPKCS1_5Signature:(NSData *)signature forData:(NSData *)signedData usingKey:(SecKeyRef)key andSHAHashLength:(NSUInteger)SHALength {

    RSAPKCS1_5 *rsaAlgorithm = [[RSAPKCS1_5 alloc] initWithData:signedData Cert:key andSHADigestLength:SHALength];
    return [rsaAlgorithm verifySignature:signature];
}

#pragma mark Get JWK Methods

-(SecKeyRef)getKeyRef {
    
    NSDictionary *tokenHeader = [token getHeader];
    
    if ([tokenHeader objectForKey:@"kid"]) {
        
        if ([token getType] == kJWTTypeOpenIDConnectIDToken) {
            
            return [self getKeyRefFromIssuer:[token getClaimValueFromPayload:@"iss"] usingKID:[tokenHeader objectForKey:@"kid"]];
        
        } else if ([token getType] == kJWTTypeOAuth20AccessToken) {
            
            return [self getKeyRefFromPingFederateOAuthKeyStore:[token getClaimValueFromPayload:@"iss"] usingKID:[tokenHeader objectForKey:@"kid"]];

        } else {
            
            return nil;
        }
        
    } else if ([tokenHeader objectForKey:@"x5u"]) {
        
        // find a key using x5u (URL to PEM)
        return [JWK getSecKeyRefForPEMCertificateAtUrl:[token getClaimValueFromHeader:@"x5u"]];
        
    } else if ([tokenHeader objectForKey:@"x5c"]) {
        
        //x509 Certificate chain
        
    } else if ([tokenHeader objectForKey:@"x5t"]) {
        
        //x509 Certificate thumbprint
        
    } else {
        // not sure how to get the key...
        return nil;
    }

    return nil;
}

-(SecKeyRef)getKeyRefFromIssuer:(NSString *)issuer usingKID:(NSString *)kid {
    
    MetadataHelper *OIDCMetadata = [[MetadataHelper alloc] initWithIssuer:issuer];
    
    JWKS *keystore = [[JWKS alloc] initWithUrl:[OIDCMetadata getJWKSUrl]];
    JWK *signingKey = [keystore getJWKusingKID:kid];
    return [signingKey getSecKeyRef];
}

-(SecKeyRef)getKeyRefFromPingFederateOAuthKeyStore:(NSString *)pfbaseurl usingKID:(NSString *)kid {
    
    return [JWK getSecKeyRefForPEMCertificateAtUrl:[NSString stringWithFormat:@"%@/ext/oauth/x509/kid?v=%@", pfbaseurl, kid]];
}


@end
