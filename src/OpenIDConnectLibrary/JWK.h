//
//  JWK.h
//  Copyright (c) 2014 Ping Identity. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface JWK : NSObject {

    NSString *keyIssuer;
    NSMutableDictionary *_jwk;
}

typedef enum registeredUsage {
    kJWKUsageSigning = 0,
    kJWKUsageEncryption,
} JWKUsage;

#define JWKUsageArray @"sig", @"enc"

@property (nonatomic, retain) NSString *kid;
@property (nonatomic) JWKUsage usage;

-(id)initWithDictionary:(NSDictionary *)jwk;
-(void)setIssuer:(NSString *)issuer;
-(NSString *)getIssuer;

-(SecKeyRef)getSecKeyRef;
+(SecKeyRef)getSecKeyRefForPEMCertificateAtUrl:(NSString *)url;

@end
