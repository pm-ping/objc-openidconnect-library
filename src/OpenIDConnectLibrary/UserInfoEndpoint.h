//
//  UserInfoEndpoint.h
//  Copyright (c) 2014 Ping Identity. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface UserInfoEndpoint : NSObject {
    
    NSURL *UserInfoEndpointUrl;
    NSDictionary *UserInfoContents;
}

-(id)init;
-(id)initWithIssuer:(NSString *)issuer andAccessToken:(NSString *)accessToken;

-(id)getClaimValue:(NSString *)claim;
-(NSDictionary *)getClaims;


@end
