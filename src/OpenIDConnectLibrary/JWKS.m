//
//  JWKS.m
//  Copyright (c) 2014 Ping Identity. All rights reserved.
//

#import "JWKS.h"
#import "JWK.h"
#import "HttpHelper.h"

@implementation JWKS

-(id)initWithUrl:(NSURL *)url {

    self = [super init];
    
    if(self) {
        
        NSError *jwks_error = nil;
        HttpResponse *jwks = [HttpHelper getUrl:[url absoluteString] withAuthZHeader:nil];
        NSDictionary *jsonJWKS = [NSJSONSerialization JSONObjectWithData:jwks.responseData options:kNilOptions error:&jwks_error];
        
        _jwksRawKeys = [jsonJWKS objectForKey:@"keys"];

        NSMutableArray *jwksKeysArray = [[NSMutableArray alloc] init];
        
        for (NSDictionary *key in _jwksRawKeys) {
            JWK *thisJWK = [[JWK alloc] initWithDictionary:key];
            [jwksKeysArray addObject:thisJWK];
        }
        
        _jwksKeys = jwksKeysArray;
    }

    return self;
}

-(JWK *)getJWKusingKID:(NSString *)kid {

    JWK *returnKey = nil;
    
    //Predicates maybe...
    
    for(JWK *key in _jwksKeys) {
        if ([key.kid isEqualToString:kid]) {
            returnKey = key; // spec says return last if duplicates, so rather than directly return, keep looping
        }
    }
    
    return returnKey;
}

-(JWK *)getJWKusingKID:(NSString *)kid forUse:(JWKUsage)usage {
    
    JWK *returnKey = nil;
    
    //Predicates maybe...
    
    for(JWK *key in _jwksKeys) {
        if ([key.kid isEqualToString:kid]) {
            if(key.usage == usage) {
                returnKey = key;
            }
        }
    }
    
    return returnKey;
}


@end
