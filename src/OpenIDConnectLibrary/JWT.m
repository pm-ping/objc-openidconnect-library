//
//  JWT.m
//  Copyright (c) 2014 Ping Identity. All rights reserved.
//

#import "JWT.h"
#import "JWS.h"
#import "JWA.h"

#import "Utils.h"

@implementation JWT

JWTType _jwtType;

#pragma mark Static Methods

+(BOOL)isJWT:(NSString *)token {

    if (token != nil) {
        return [token rangeOfString:@"."].location != NSNotFound;
    }
    
    return NO;
}

-(BOOL)isJWS {
    
    return [JWA getAlgorithmType:self] != kJWAAlgorithmNone;
}

-(BOOL)isSigned {

    return [self isJWS];
}

-(BOOL)isJWE {

    //TODO: Add JWE support
    return NO;
}

-(BOOL)isEncrypted {
    return [self isJWE];
}

-(id)init {

    self = [super init];
    
    if (self)
    {
        _jwtHeader = [[NSMutableDictionary alloc] init];
        _jwtPayload = [[NSMutableDictionary alloc] init];
        _jwtRawHeader = @"";
        _jwtRawPayload = @"";
        _jwtRawSignature = @"";
        _jwtSignature = [Utils base64UrlDecodeString:_jwtRawSignature];
    }
    
    return self;
}

-(id)initWithBase64UrlEncodedToken:(NSString *)token {
    
    self = [super init];
    
    if (self)
    {
        NSError *error = nil;
        
        if ([JWT isJWT:token]) {
            
            NSArray *jwtComponents = [token componentsSeparatedByString:@"."];
            
            if ([jwtComponents count] == 3) { // JWS/JWT
                
                _jwtRawString = token;
                
                _jwtRawHeader = [jwtComponents objectAtIndex:0];
                NSData *jwtHeaderData = [Utils base64UrlDecodeString:_jwtRawHeader];
                _jwtHeader = [NSJSONSerialization JSONObjectWithData:jwtHeaderData options:kNilOptions error:&error];

                _jwtRawPayload = [jwtComponents objectAtIndex:1];
                NSData *jwtPayloadData = [Utils base64UrlDecodeString:_jwtRawPayload];
                _jwtPayload = [NSJSONSerialization JSONObjectWithData:jwtPayloadData options:kNilOptions error:&error];

                _jwtRawSignature = [jwtComponents objectAtIndex:2];
                _jwtSignature = [Utils base64UrlDecodeString:_jwtRawSignature];

                return self;
                
            } else if ([jwtComponents count] == 4) { // JWS JSON Serialization

                //TODO: Support JWS JSON Serialization
                return nil;
                
            } else if ([jwtComponents count] == 5) { // JWE

                //TODO: Support JWE
                return nil;
                
            } else {
                
                // Unknown JWT format
                return nil;
            }
            
        } else {
            
            // Not a JWT
            return nil;
        }
        
    }
    return self;
    
}

-(id)initWithBase64UrlEncodedToken:(NSString *)token ofType:(JWTType)type {

    JWT *thisToken = [self initWithBase64UrlEncodedToken:token];
    _jwtType = type;
    return thisToken;
}

-(JWTType)getType {

    return _jwtType;
}

-(void)setType:(JWTType)type {
    
    _jwtType = type;
}

-(NSDictionary *)getHeader {

    return _jwtHeader;
}

-(NSDictionary *)getPayload {
    
    return _jwtPayload;
}

-(NSData *)getSignature {

    return _jwtSignature;
}

-(NSString *)getSignatureAsString {
    
    return _jwtRawSignature;
}

-(id)getClaimValueFromPayload:(NSString *)claim {
    
    return [_jwtPayload objectForKey:claim];
}

-(id)getClaimValueFromHeader:(NSString *)claim {
    
    return [_jwtHeader objectForKey:claim];
}

-(NSString *)getSignedData {
    return [NSString stringWithFormat:@"%@.%@", _jwtRawHeader, _jwtRawPayload];
}


#pragma mark JWT Building Methods
-(void)setPayloadWithJSONString:(NSString *)payload {
    
    _jwtRawSignature = @"";
    _jwtSignature = [Utils base64UrlDecodeString:_jwtRawSignature];
    
    [_jwtHeader removeAllObjects];
    [_jwtHeader setValue:@"none" forKey:@"alg"];
    
    [_jwtPayload removeAllObjects];

    NSError *error = nil;
    NSDictionary *newPayload = [NSJSONSerialization JSONObjectWithData:[payload dataUsingEncoding:NSUTF8StringEncoding] options:kNilOptions error:&error];
    
    [_jwtPayload addEntriesFromDictionary:newPayload];
    
}

-(void)setPayloadWithDictionary:(NSDictionary *)payload {
    
    _jwtRawSignature = @"";
    _jwtSignature = [Utils base64UrlDecodeString:_jwtRawSignature];
    
    [_jwtHeader removeAllObjects];
    [_jwtHeader setValue:@"none" forKey:@"alg"];

    [_jwtPayload removeAllObjects];
    [_jwtPayload addEntriesFromDictionary:payload];
}

-(NSString *)jwtAsString {
    
    NSError *error = nil;
    
    NSData *encodedHeader = [NSJSONSerialization dataWithJSONObject:_jwtHeader options:kNilOptions error:&error];
    NSData *encodedPayload = [NSJSONSerialization dataWithJSONObject:_jwtHeader options:kNilOptions error:&error];
    
    NSString *base64UrlEncodedHeader = [Utils base64UrlEncodeData:encodedHeader];
    NSString *base64UrlEncodedPayload = [Utils base64UrlEncodeData:encodedPayload];
    NSString *base64UrlEncodedSignature = [Utils base64UrlEncodeData:_jwtSignature];
    
    return [NSString stringWithFormat:@"%@.%@.%@", base64UrlEncodedHeader, base64UrlEncodedPayload, base64UrlEncodedSignature];
}

@end
