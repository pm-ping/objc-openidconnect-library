//
//  MetadataHelper.h
//  Copyright (c) 2014 Ping Identity. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface MetadataHelper : NSObject {
    
    NSDictionary *OpenIDConnectMetadata;
}

-(id)init;
-(id)initWithIssuer:(NSString *)issuer;

-(id)getValue:(NSString *)value;
-(NSURL *)getJWKSUrl;
-(NSURL *)getUserInfoEndpointUrl;
-(NSURL *)getAuthorizationEndpointUrl;
-(NSURL *)getTokenEndpointUrl;

@end
