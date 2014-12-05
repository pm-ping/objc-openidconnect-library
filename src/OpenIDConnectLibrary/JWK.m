//
//  JWK.m
//  Copyright (c) 2014 Ping Identity. All rights reserved.
//

#import "JWK.h"
#import "Utils.h"
#import "HttpHelper.h"
#import "CertHelper.h"
#import "KeychainHelper.h"

@implementation JWK

-(id)initWithDictionary:(NSDictionary *)jwk {
    
    self = [super init];
    
    if(self) {
        _jwk = [[NSMutableDictionary alloc] initWithDictionary:jwk];
        _kid = [_jwk objectForKey:@"kid"];
    }
    
    return self;
}

-(void)setIssuer:(NSString *)issuer {

    keyIssuer = issuer;
}

-(NSString *)getIssuer {
    
    return keyIssuer;
}

-(NSString *)getValue:(NSString *)parameter {
    
    return [_jwk objectForKey:parameter];
}

-(SecKeyRef)getSecKeyRef {
    
    if ([[_jwk objectForKey:@"kty"] isEqualToString:@"RSA"]) {
        
        NSData *modulus = [Utils base64UrlDecodeString:[_jwk objectForKey:@"n"]];
        NSData *exponent = [Utils base64UrlDecodeString:[_jwk objectForKey:@"e"]];
        
        return [CertHelper getPublicCertUsingModulus:modulus exponent:exponent];
        
    } else if ([[_jwk objectForKey:@"kty"] isEqualToString:@"EC"]) {
        
        // Not Supported
        return nil;
    }
    
    return nil;
}

+(SecKeyRef)getSecKeyRefForPEMCertificateAtUrl:(NSString *)url {
    
    SecKeyRef returnReference = nil;
    
    // Grab key from keychain if it has been stored there
    returnReference = [KeychainHelper getPublicCertFromKeyChainByIssuer:url];
    
    if (!returnReference) {
        
        HttpResponse *response = [HttpHelper getUrl:url withAuthZHeader:nil];
        
        if (response.responseCode == 200) {
            
            NSString *publicCert = [[NSString alloc] initWithData:response.responseData encoding:NSUTF8StringEncoding];
            NSString *formattedCert = [[publicCert stringByReplacingOccurrencesOfString:@"-----BEGIN CERTIFICATE-----\n" withString:@""] stringByReplacingOccurrencesOfString:@"\n-----END CERTIFICATE-----\n" withString:@""];
            
            NSLog(@"Retrieved certificate: %@", formattedCert);
            
            returnReference = [CertHelper getPublicCertFromX509Data:[Utils base64UrlDecodeString:formattedCert]];
            
            // Store this in the keychain for future use:
            [KeychainHelper storePublicCertInKeyChain:returnReference keychainIdentifier:url];
            
        } else {
            
            NSLog(@"Failed to retrieve certificate");
            return nil;
        }
    }
    
    return returnReference;
}

@end
