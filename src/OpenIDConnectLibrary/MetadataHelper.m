//
//  MetadataHelper.m
//  Copyright (c) 2014 Ping Identity. All rights reserved.
//

#import "MetadataHelper.h"
#import "HttpHelper.h"

@implementation MetadataHelper

-(id)init {
    
    if(self = [super init]) {
        
        return self;
    }
    
    return nil;
}

-(id)initWithIssuer:(NSString *)issuer {
    
    self = [self init];

    NSString *wellKnownUrl = [NSString stringWithFormat:@"%@/.well-known/openid-configuration", issuer];
    NSLog(@"Retrieving JWKS url from .well-known url: %@", wellKnownUrl);
    
    HttpResponse *response = [HttpHelper getUrl:wellKnownUrl withAuthZHeader:nil];
    
    if(response.responseCode == 200) {
        NSError *error = nil;
        OpenIDConnectMetadata = [NSJSONSerialization JSONObjectWithData:response.responseData options:kNilOptions error:&error];

    } else {
        return nil;
    }
    
    return self;
}

-(id)getValue:(NSString *)value {
    
    return [OpenIDConnectMetadata objectForKey:value];
}


-(NSURL *)getJWKSUrl {
    
    return [NSURL URLWithString:[OpenIDConnectMetadata objectForKey:@"jwks_uri"]];
}

-(NSURL *)getUserInfoEndpointUrl {
    
    return [NSURL URLWithString:[OpenIDConnectMetadata objectForKey:@"userinfo_endpoint"]];
}

-(NSURL *)getAuthorizationEndpointUrl {
    
    return [NSURL URLWithString:[OpenIDConnectMetadata objectForKey:@"authorization_endpoint"]];
}

-(NSURL *)getTokenEndpointUrl {
    
    return [NSURL URLWithString:[OpenIDConnectMetadata objectForKey:@"token_endpoint"]];
}


@end
