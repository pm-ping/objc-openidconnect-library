//
//  JWT.h
//  Copyright (c) 2014 Ping Identity. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface JWT : NSObject {
    
    NSString *_jwtRawString;
    NSMutableDictionary *_jwtHeader;
    NSMutableDictionary *_jwtPayload;
    NSString *_jwtRawHeader;
    NSString *_jwtRawPayload;
    NSString *_jwtRawSignature;
    NSData *_jwtSignature;
}

typedef enum jwtType {
    kJWTTypeOAuth20AccessToken = 0,
    kJWTTypeOpenIDConnectIDToken
} JWTType;

typedef enum registeredJWTClaims {
    kJWTClaimIssuer = 0,
    kJWTClaimSubject,
    kJWTClaimAudience,
    kJWTClaimExpirationTime,
    kJWTClaimNotBefore,
    kJWTClaimIssuedAt,
    kJWTClaimID
} JWTClaim;

#define JWTClaimsArray @"iss", @"sub", @"aud", @"exp", @"nbf", @"iat", @"jti"

typedef enum registeredJWTHeaderParameters {
    kJWTHeaderParameterType = 0,
    kJWTHeaderParameterContentType
} JWTHeaderParameter;

#define JWTHeaderParameters @"typ", @"cty"


+(BOOL)isJWT:(NSString *)token;
-(BOOL)isJWS;
-(BOOL)isSigned;
-(BOOL)isJWE;
-(BOOL)isEncrypted;

-(id)init;
-(id)initWithBase64UrlEncodedToken:(NSString *)token;
-(id)initWithBase64UrlEncodedToken:(NSString *)token ofType:(JWTType)type;

-(JWTType)getType;
-(void)setType:(JWTType)type;

-(NSDictionary *)getHeader;
-(NSDictionary *)getPayload;
-(NSData *)getSignature;
-(NSString *)getSignatureAsString;
-(NSString *)getSignedData;

-(id)getClaimValueFromPayload:(NSString *)claim;
-(id)getClaimValueFromHeader:(NSString *)claim;

-(void)setPayloadWithJSONString:(NSString *)payload;
-(void)setPayloadWithDictionary:(NSDictionary *)payload;

@end
