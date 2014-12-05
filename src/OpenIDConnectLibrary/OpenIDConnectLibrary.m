//
//  OpenIDConnectLibrary.m
//  Copyright (c) 2013 Ping Identity. All rights reserved.
//

#import "OpenIDConnectLibrary.h"
#import "JWT.h"
#import "TokenValidationHelper.h"
#import "Utils.h"


@implementation OpenIDConnectLibrary

+(NSDictionary *)parseIDToken:(NSString *)idToken forClient:(OAuth2Client *)client {

    NSArray *results;
    JWT *jwt = [[JWT alloc] initWithBase64UrlEncodedToken:idToken ofType:kJWTTypeOpenIDConnectIDToken];
    
    if ([TokenValidationHelper validateIDToken:jwt forClient:client validationResults:&results]) {
        return [jwt getPayload];
    } else
    {
        return nil;
    }
}

+(BOOL)validateIDToken:(NSString *)idToken forClient:(OAuth2Client *)client {

    NSArray *results;
    JWT *jwt = [[JWT alloc] initWithBase64UrlEncodedToken:idToken ofType:kJWTTypeOpenIDConnectIDToken];
    return [TokenValidationHelper validateIDToken:jwt forClient:client validationResults:&results];
}

+(BOOL)validateJWTIDToken:(JWT *)idToken forClient:(OAuth2Client *)client {
    
    NSArray *results;
    return [TokenValidationHelper validateIDToken:idToken forClient:client validationResults:&results];
}

+(NSString *)getParsedHeaderForToken:(NSString *)token {
    
    JWT *jwt = [[JWT alloc] initWithBase64UrlEncodedToken:token ofType:kJWTTypeOpenIDConnectIDToken];
    return [Utils jsonPrettyPrint:[jwt getPayload]];
}

+(NSString *)getParsedPayloadForToken:(NSString *)token {
    
    JWT *jwt = [[JWT alloc] initWithBase64UrlEncodedToken:token ofType:kJWTTypeOpenIDConnectIDToken];
    return [Utils jsonPrettyPrint:[jwt getPayload]];
}

@end
