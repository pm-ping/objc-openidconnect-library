//
//  TokenValidationHelper.h
//  Copyright (c) 2013 Paul Meyer. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "OAuth2Client.h"
#import "JWT.h"

@interface TokenValidationHelper : NSObject

+(BOOL)validateIDToken:(JWT *)idToken forClient:(OAuth2Client *)client validationResults:(NSArray **)results;
+(BOOL)validateAccessToken:(JWT *)accessToken forClient:(OAuth2Client *)client validationResults:(NSArray **)results;

@end
