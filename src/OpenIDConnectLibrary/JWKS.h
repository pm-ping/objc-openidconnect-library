//
//  JWKS.h
//  Copyright (c) 2014 Ping Identity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "JWK.h"

@interface JWKS : NSObject {
    
    NSArray *_jwksRawKeys; // "keys" array (as downloaded)
    NSArray *_jwksKeys; // "keys" array (converted to an Array of JWKs)
}

-(id)initWithUrl:(NSURL *)url;
-(JWK *)getJWKusingKID:(NSString *)kid;
-(JWK *)getJWKusingKID:(NSString *)kid forUse:(JWKUsage)usage;

@end
