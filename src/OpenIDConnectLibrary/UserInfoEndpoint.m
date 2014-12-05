//
//  UserInfoEndpoint.m
//  Copyright (c) 2014 Ping Identity. All rights reserved.
//

#import "UserInfoEndpoint.h"
#import "MetadataHelper.h"
#import "HttpHelper.h"

@implementation UserInfoEndpoint

-(id)init {
    
    if (self = [super init]) {
        return self;
    }
    
    return nil;
}

-(id)initWithIssuer:(NSString *)issuer andAccessToken:(NSString *)accessToken {

    self = [self init];
    
    MetadataHelper *OIDCMetadata = [[MetadataHelper alloc] initWithIssuer:issuer];
    UserInfoEndpointUrl = [OIDCMetadata getUserInfoEndpointUrl];
    
    HttpResponse *httpResponse = [HttpHelper getUrl:[UserInfoEndpointUrl absoluteString] withAuthZHeader:[NSString stringWithFormat:@"Bearer %@", accessToken]];
    
    if (httpResponse.responseCode == 200) {

        NSError *error;
        UserInfoContents = [NSJSONSerialization JSONObjectWithData:httpResponse.responseData options:kNilOptions error:&error];
        return self;

    } else {
        
        NSString *errorMessage = [NSString stringWithFormat:@"An error occurred\r\nHTTP Response Code: %lu\r\nHTTP Response:\r\n%@", (unsigned long)httpResponse.responseCode, [[NSString alloc] initWithData:httpResponse.responseData encoding:NSUTF8StringEncoding]];
        NSLog(@"FAILURE: Error grabbing user info: %@", errorMessage);
    }
    
    return nil;
}

-(id)getClaimValue:(NSString *)claim {
    
    return [UserInfoContents objectForKey:claim];
}

-(NSDictionary *)getClaims {
    
    return UserInfoContents;
}


@end
