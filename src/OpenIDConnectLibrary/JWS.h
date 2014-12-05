//
//  JWS.h
//  Copyright (c) 2014 Ping Identity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "JWT.h"
#import "JWA.h"

@interface JWS : NSObject {

    JWAAlgorithm signingAlgorithm;
    NSData *symmetricKey;
    JWT *token;
    SecKeyRef asymmetricKeyRef;
}

typedef enum registeredJWSHeaderParameters {
    kJWSHeaderParameterAlgorithm = 0,
    kJWSHeaderParameterJWKSetUrl,
    kJWSHeaderParameterJSONWebKey,
    kJWSHeaderParameterKeyID,
    kJWSHeaderParameterX509Url,
    kJWSHeaderParameterX509CertificateChain,
    kJWSHeaderParameterX509CertificateSHA1Thumbprint,
    kJWSHeaderParameterType,
    kJWSHeaderParameterContentType,
    kJWSHeaderParameterCritical
} JWSHeaderParameter;

#define JWSHeaderParameters @"alg", @"jku", @"jwk", @"kid", @"x5u", @"x5c", @"x5t", @"typ", @"cty", @"crit"

-(id)init;
-(id)initWithJWT:(JWT *)jwt;
-(JWAAlgorithm)getAlgorithm;

+(JWT *)signJWT:(JWT *)jwt;
+(JWT *)signJWTPayloadAsDictionary:(NSDictionary *)payload;
+(JWT *)signJWTPayloadAsJSONString:(NSString *)payload;

-(void)setSymmetricKey:(NSData *)key;
-(BOOL)verifySignature;

@end
