//
//  TokenValidationHelper.m
//  Copyright (c) 2013 Paul Meyer. All rights reserved.
//

#import "TokenValidationHelper.h"
#import "JWS.h"
#import "JWT.h"
#import "CertHelper.h"
#import "SHA.h"
#import "HMAC.h"
#import "RSAPKCS1_5.h"
#import "Utils.h"
#import "TokenValidationResult.h"

#import <Security/Security.h>


@implementation TokenValidationHelper

-(id) init
{
    self = [super init];
    
    if (self)
    {
    }
    
    return self;
}

+(BOOL) validateAccessToken:(JWT *)accessToken forClient:(OAuth2Client *)client validationResults:(NSArray **)results {
    
    NSLog(@"---[ Validating JWT OAuth2 access token ]------");
    
    NSMutableArray *validationResults = [[NSMutableArray alloc] init];
    BOOL TokenValid = YES;
    
    // No defined rules to check the access token.  But we should test to our applications satisfaction, ie:
    // 1. Issuer is trusted
    // 2. Audience is me
    // 3. Token hasn't expired
    // 4. Signature is valid
    
    // Does the issuer match the issuer (iss) in the token.
    if ([self checkValue:[client baseUrl] forKey:@"iss" inDictionary:[accessToken getPayload] okayToNotExist:NO]) {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Issuer" Detail:[[NSString alloc] initWithFormat:@"Issuer from token (%@) matches Issuer from OAuth request (%@)", [accessToken getClaimValueFromPayload:@"iss"], [client baseUrl]] Result:kJWTValidationResultSuccess]];
    } else {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Issuer" Detail:[[NSString alloc] initWithFormat:@"Issuer from token (%@) DOES NOT match Issuer from OAuth request (%@)", [accessToken getClaimValueFromPayload:@"iss"], [client baseUrl]] Result:kJWTValidationResultFailure]];
        NSLog(@"Issuer mismatch!");
        TokenValid = NO;
    }
    
    // client_id SHOULD match the client_id that requested the token
    if ([self checkValue:[client getOAuthRequestParameter:kOAuth2RequestParamClientId] forKey:@"client_id" inDictionary:[accessToken getPayload] okayToNotExist:NO]) {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Audience" Detail:[[NSString alloc] initWithFormat:@"Audience from token (%@) matches OAuth client_id (%@)", [accessToken getClaimValueFromPayload:@"client_id"], [client getOAuthRequestParameter:kOAuth2RequestParamClientId]] Result:kJWTValidationResultSuccess]];
    } else {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Audience" Detail:[[NSString alloc] initWithFormat:@"Audience from token (%@) DOES NOT match OAuth client_id (%@)", [accessToken getClaimValueFromPayload:@"client_id"], [client getOAuthRequestParameter:kOAuth2RequestParamClientId]] Result:kJWTValidationResultFailure]];
        NSLog(@"Audience mismatch!");
        TokenValid = NO;
    }
    
    // token MUST not have expired
    if ([self validateTimeClaimForToken:accessToken Claim:@"exp" skewSeconds:0]) {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Token Expiry" Detail:[[NSString alloc] initWithFormat:@"Token expiry (%@) is after now (%@)", [NSDate dateWithTimeIntervalSince1970:[[accessToken getClaimValueFromPayload:@"exp"] doubleValue]], [NSDate date]] Result:kJWTValidationResultSuccess]];
    } else {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Token Expiry" Detail:[[NSString alloc] initWithFormat:@"Token has expired.  (%@) is before now (%@)", [NSDate dateWithTimeIntervalSince1970:[[accessToken getClaimValueFromPayload:@"exp"] doubleValue]], [NSDate date]] Result:kJWTValidationResultFailure]];
        NSLog(@"Token has expired!");
        TokenValid = NO;
    }
    
    // validate the signature
    JWS *jws = [[JWS alloc] initWithJWT:accessToken];
    
    if ([jws verifySignature]) {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Signature" Detail:@"Digital Signature Valid" Result:kJWTValidationResultSuccess]];
    } else {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Signature" Detail:@"Digital Signature INVALID" Result:kJWTValidationResultFailure]];
        NSLog(@"Invalid signature!");
        TokenValid = NO;
    }
    
    NSLog(@"---[ Verification Complete ]------");
    
    *results = validationResults;
    return TokenValid;
}

+(BOOL) validateIDTokenUsingBasicClientProfile:(JWT *)idToken forClient:(OAuth2Client *)client validationResults:(NSArray **)results {
 
    // Basic Client Profile (OIDC Core Section 3.1.3.7)
    
    NSMutableArray *validationResults = [[NSMutableArray alloc] init];
    BOOL TokenValid = YES;
    
    // #1 - Decrypt the token if encrypted
    // Not Applicable - Token not encrypted
    [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Decrypt token if Encrypted" Detail:@"Token Not Encrypted" Result:kJWTValidationResultSkipped]];
    
    // #2 - Does the issuer match the issuer (iss) in the token.
    if ([self checkValue:[client baseUrl] forKey:@"iss" inDictionary:[idToken getPayload] okayToNotExist:NO]) {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Issuer" Detail:[[NSString alloc] initWithFormat:@"Issuer from token (%@) matches Issuer from OAuth request (%@)", [idToken getClaimValueFromPayload:@"iss"], [client baseUrl]] Result:kJWTValidationResultSuccess]];
    } else {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Issuer" Detail:[[NSString alloc] initWithFormat:@"Issuer from token (%@) DOES NOT match Issuer from OAuth request (%@)", [idToken getClaimValueFromPayload:@"iss"], [client baseUrl]] Result:kJWTValidationResultFailure]];
        NSLog(@"Issuer mismatch!");
        TokenValid = NO;
    }
    
    // #3 - Does the audience (aud) match the OAuth client id.
    // #4 - Does the token contain multiple audiences.
    // #5 - Validate the azp claim if present
    if ([self validateAudienceForToken:idToken Audience:[client getOAuthRequestParameter:kOAuth2RequestParamClientId]]) {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Audience" Detail:[[NSString alloc] initWithFormat:@"Audience from token (%@) matches client_id from OAuth request (%@)", [idToken getClaimValueFromPayload:@"aud"], [client getOAuthRequestParameter:kOAuth2RequestParamClientId]] Result:kJWTValidationResultSuccess]];
    } else {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Audience" Detail:[[NSString alloc] initWithFormat:@"Audience from token (%@) DOES NOT match client_id from OAuth request (%@)", [idToken getClaimValueFromPayload:@"aud"], [client getOAuthRequestParameter:kOAuth2RequestParamClientId]] Result:kJWTValidationResultFailure]];
        NSLog(@"Audience mismatch!");
        TokenValid = NO;
    }
    
    // #6, 7 & 8 - Verify the signature (optional)
    // The id_token was received directly from token endpoint over TLS, therefore signature verification is optional.");
    // However, because we may be using a cached token, lets validate the certificate to be sure:
       [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Signature" Detail:@"Basic Client Profile - token received directly from token endpoint, signature verification optional." Result:kJWTValidationResultSkipped]];

    //    if ([JWS verifySignatureForJWT:idToken]) {
//        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Signature" Detail:@"Digital Signature Valid" Result:kJWTValidationResultSuccess]];
//    } else {
//        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Signature" Detail:@"Digital Signature INVALID" Result:kJWTValidationResultFailure]];
//        NSLog(@"Invalid signature!");
//        TokenValid = NO;
//    }
    
    // #9 - Current time before id_token expiry (exp)
    if ([self validateTimeClaimForToken:idToken Claim:@"exp" skewSeconds:0]) {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Token Expiry" Detail:[[NSString alloc] initWithFormat:@"Token expiry (%@) is after now (%@)", [NSDate dateWithTimeIntervalSince1970:[[idToken getClaimValueFromPayload:@"exp"] doubleValue]], [NSDate date]] Result:kJWTValidationResultSuccess]];
    } else {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Token Expiry" Detail:[[NSString alloc] initWithFormat:@"Token has expired.  (%@) is before now (%@)", [NSDate dateWithTimeIntervalSince1970:[[idToken getClaimValueFromPayload:@"exp"] doubleValue]], [NSDate date]] Result:kJWTValidationResultFailure]];
        NSLog(@"Token has expired!");
        TokenValid = NO;
    }
    
    // #10 - Was the token issued within acceptable timeframe (iat)
    // Client Specific - We will used a static value of 60 mins skew (ie token must have been issued within the last 60 mins)
    if ([self checkTimeIsSameOrEarlierForClaim:@"iat" inToken:idToken skewSeconds:-3600]) {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Token Recently Issued" Detail:[[NSString alloc] initWithFormat:@"Token issued within last 60 mins (%@)", [NSDate dateWithTimeIntervalSince1970:[[idToken getClaimValueFromPayload:@"iat"] doubleValue]]] Result:kJWTValidationResultSuccess]];
    } else {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Token Recently Issued" Detail:[[NSString alloc] initWithFormat:@"Token issued longer than 60 mins ago (%@)", [NSDate dateWithTimeIntervalSince1970:[[idToken getClaimValueFromPayload:@"iat"] doubleValue]]] Result:kJWTValidationResultFailure]];
        NSLog(@"Token was issued too long ago!");
        TokenValid = NO;
    }
    
    // #11 - Does the nonce match the value sent in the authentication request
    // Only REQUIRED if the Nonce parameter is present - should also check the nonce for replays etc
    if([self checkValue:[client getOAuthRequestParameter:kOAuth2RequestParamNonce] forKey:@"nonce" inDictionary:[idToken getPayload] okayToNotExist:YES]) {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Nonce" Detail:[[NSString alloc] initWithFormat:@"Nonce was present in token (%@) and matches nonce from request (%@)", [idToken getClaimValueFromPayload:@"nonce"], [client getOAuthRequestParameter:kOAuth2RequestParamNonce]] Result:kJWTValidationResultSuccess]];
    } else {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Nonce" Detail:[[NSString alloc] initWithFormat:@"Nonce was present in token (%@) and does not match nonce from request (%@)", [idToken getClaimValueFromPayload:@"nonce"], [client getOAuthRequestParameter:kOAuth2RequestParamNonce]] Result:kJWTValidationResultFailure]];
        NSLog(@"Nonce was present and does not match!");
        TokenValid = NO;
    }
    
    // #12 - Is the acr value appropriate for the requested authentication
    // Client specific - could test this to say - I expected multi-factor authentication and only got single-factor so fail.
    [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify appropriate acr value" Detail:@"Client specific - not tested" Result:kJWTValidationResultNotApplicable]];
    
    // #13 - Is the auth_time within an acceptable range
    // Client specific - if auth_time is present - then user must have authenticated > x mins ago.
    [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify auth_time within acceptable range" Detail:@"Client specific - not tested" Result:kJWTValidationResultNotApplicable]];
    
    NSLog(@"ID Token validation complete");
    
    *results = validationResults;
    return TokenValid;
}


+(BOOL) validateIDTokenUsingImplicitClientProfile:(JWT *)idToken forClient:(OAuth2Client *)client validationResults:(NSArray **)results {
    
    // Implicit Client Profile (OIDC Core Section 3.1.3.7 + additions for Implicit profile 3.2.2.11)
    
    NSMutableArray *validationResults = [[NSMutableArray alloc] init];
    BOOL TokenValid = YES;
    
    // #1 - Decrypt the token if encrypted
    // Not Applicable - Token not encrypted
    [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Decrypt token if Encrypted" Detail:@"Token Not Encrypted" Result:kJWTValidationResultSkipped]];
    
    // #2 - Does the issuer match the issuer (iss) in the token.
    if ([self checkValue:[client baseUrl] forKey:@"iss" inDictionary:[idToken getPayload] okayToNotExist:NO]) {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Issuer" Detail:[[NSString alloc] initWithFormat:@"Issuer from token (%@) matches Issuer from OAuth request (%@)", [idToken getClaimValueFromPayload:@"iss"], [client baseUrl]] Result:kJWTValidationResultSuccess]];
    } else {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Issuer" Detail:[[NSString alloc] initWithFormat:@"Issuer from token (%@) DOES NOT match Issuer from OAuth request (%@)", [idToken getClaimValueFromPayload:@"iss"], [client baseUrl]] Result:kJWTValidationResultFailure]];
        NSLog(@"Issuer mismatch!");
        TokenValid = NO;
    }
    
    // #3 - Does the audience (aud) match the OAuth client id.
    // #4 - Does the token contain multiple audiences.
    // #5 - Validate the azp claim if present
    if ([self validateAudienceForToken:idToken Audience:[client getOAuthRequestParameter:kOAuth2RequestParamClientId]]) {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Audience" Detail:[[NSString alloc] initWithFormat:@"Audience from token (%@) matches client_id from OAuth request (%@)", [idToken getClaimValueFromPayload:@"aud"], [client getOAuthRequestParameter:kOAuth2RequestParamClientId]] Result:kJWTValidationResultSuccess]];
    } else {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Audience" Detail:[[NSString alloc] initWithFormat:@"Audience from token (%@) DOES NOT match client_id from OAuth request (%@)", [idToken getClaimValueFromPayload:@"aud"], [client getOAuthRequestParameter:kOAuth2RequestParamClientId]] Result:kJWTValidationResultFailure]];
        NSLog(@"Audience mismatch!");
        TokenValid = NO;
    }
    
    // #6, 7 & 8 - Verify the signature (optional)
    // For the Implicit profile, signature verification is REQUIRED
    JWS *jws = [[JWS alloc] initWithJWT:idToken];

    if ([jws verifySignature]) {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Signature" Detail:@"Digital Signature Valid" Result:kJWTValidationResultSuccess]];
    } else {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Signature" Detail:@"Digital Signature INVALID" Result:kJWTValidationResultFailure]];
        NSLog(@"Invalid signature!");
        TokenValid = NO;
    }
    
    // #9 - Current time before id_token expiry (exp)
    if ([self validateTimeClaimForToken:idToken Claim:@"exp" skewSeconds:0]) {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Token Expiry" Detail:[[NSString alloc] initWithFormat:@"Token expiry (%@) is after now (%@)", [NSDate dateWithTimeIntervalSince1970:[[idToken getClaimValueFromPayload:@"exp"] doubleValue]], [NSDate date]] Result:kJWTValidationResultSuccess]];
    } else {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Token Expiry" Detail:[[NSString alloc] initWithFormat:@"Token has expired.  (%@) is before now (%@)", [NSDate dateWithTimeIntervalSince1970:[[idToken getClaimValueFromPayload:@"exp"] doubleValue]], [NSDate date]] Result:kJWTValidationResultFailure]];
        NSLog(@"Token has expired!");
        TokenValid = NO;
    }
    
    // #10 - Was the token issued within acceptable timeframe (iat)
    // Client Specific - We will used a static value of 60 mins skew (ie token must have been issued within the last 60 mins)
    if ([self checkTimeIsSameOrEarlierForClaim:@"iat" inToken:idToken skewSeconds:-3600]) {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Token Recently Issued" Detail:[[NSString alloc] initWithFormat:@"Token issued within last 60 mins (%@)", [NSDate dateWithTimeIntervalSince1970:[[idToken getClaimValueFromPayload:@"iat"] doubleValue]]] Result:kJWTValidationResultSuccess]];
    } else {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Token Recently Issued" Detail:[[NSString alloc] initWithFormat:@"Token issued longer than 60 mins ago (%@)", [NSDate dateWithTimeIntervalSince1970:[[idToken getClaimValueFromPayload:@"iat"] doubleValue]]] Result:kJWTValidationResultFailure]];
        NSLog(@"Token was issued too long ago!");
        TokenValid = NO;
    }
    
    // #11 - Does the nonce match the value sent in the authentication request
    // For the Implicit profile, Nonce checking is REQUIRED
    if([self checkValue:[client getOAuthRequestParameter:kOAuth2RequestParamNonce] forKey:@"nonce" inDictionary:[idToken getPayload] okayToNotExist:NO]) {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Nonce" Detail:[[NSString alloc] initWithFormat:@"Nonce in token (%@) and matches nonce from request (%@)", [idToken getClaimValueFromPayload:@"nonce"], [client getOAuthRequestParameter:kOAuth2RequestParamNonce]] Result:kJWTValidationResultSuccess]];
    } else {
        [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify Nonce" Detail:[[NSString alloc] initWithFormat:@"Nonce in token (%@) and does not match nonce from request (%@)", [idToken getClaimValueFromPayload:@"nonce"], [client getOAuthRequestParameter:kOAuth2RequestParamNonce]] Result:kJWTValidationResultFailure]];
        NSLog(@"Nonce does not match!");
        TokenValid = NO;
    }
    
    // #12 - Is the acr value appropriate for the requested authentication
    // Client specific - could test this to say - I expected multi-factor authentication and only got single-factor so fail.
    [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify appropriate acr value" Detail:@"Client specific - not tested" Result:kJWTValidationResultNotApplicable]];
    
    // #13 - Is the auth_time within an acceptable range
    // Client specific - if auth_time is present - then user must have authenticated > x mins ago.
    [validationResults addObject:[[TokenValidationResult alloc] initWithTitle:@"Verify auth_time within acceptable range" Detail:@"Client specific - not tested" Result:kJWTValidationResultNotApplicable]];
    
    NSLog(@"ID Token validation complete");
    
    *results = validationResults;
    return TokenValid;
}


+(BOOL) validateIDToken:(JWT *)idToken forClient:(OAuth2Client *)client validationResults:(NSArray **)results
{
    // Determine the validation requirements based on the response_type:
    // - code == Basic Client Profile (scope contains openid)
    // - token == OAuth2 implicit grant (if scope contains openid, then userinfo possible)
    // - id_token == Implicit, no Access Token (no userinfo, just id_token)
    // - token id_token == Implicit Client Profile (scope contains openid)
    // - code token ==
    // - code id_token == Hybrid flow (Uses Implicit rules / has at_hash and c_hash)
    // - code token id_token == Hybrid flow (Uses Implicit rules / has at_hash and c_hash)
    
    if (idToken != nil) {
        
        NSString *oauthResponseType = [client getOAuthRequestParameter:kOAuth2RequestParamResponseType];
        
        NSLog(@"Validating id_token for grant type %@", oauthResponseType);
        
        if ([oauthResponseType isEqual:@"code"]) {
            // Validate id_token received via OIDC Basic Client Profile
            
            return [self validateIDTokenUsingBasicClientProfile:idToken forClient:client validationResults:results];
            
        } else if ([oauthResponseType isEqual:@"id_token"]) {
            // Validate id_token received via OIDC Implicit Client Profile
            
            return [self validateIDTokenUsingImplicitClientProfile:idToken forClient:client validationResults:results];
            
        } else if ([oauthResponseType isEqual:@"token id_token"]) {
            // Validate id_token received via OIDC Implicit Client Profile
            
            BOOL idTokenValid = [self validateIDTokenUsingImplicitClientProfile:idToken forClient:client validationResults:results];
            
            if (idTokenValid) {
                
                // Additional test when access_token provided along with id_token
                // As we have also been provided an access_token in this flow, we must verify the at_hash value
                
                
                
//                if(![self validateHash:(NSString *)[idToken getClaimValueFromPayload:@"at_hash"] forToken:[client getOAuthResponseValueForParameter:kOAuth2ResponseParamAccessToken] usingAlgorithm:idToken.signing_alg]) {
//                    NSLog(@"Access token hash does not match!");
//                    return NO;
//                }
            }
            
            NSLog(@"ID Token validation complete");
            return idTokenValid;
            
        } else if ([self isHybridFlow:oauthResponseType]) {
            // Validate id_token received via OIDC Hybrid Client Profile (rules are same as Implicit 3.3.2.12)
            
            BOOL idTokenValid = [self validateIDTokenUsingImplicitClientProfile:idToken forClient:client validationResults:results];
            
            if (idTokenValid) {
                
                // Additional test when access_token provided along with id_token
                // As we have also been provided an access_token in this flow, we must verify the at_hash value
                
                // This test is only to validate that the access_token received along with the id_token is the same
                // In a hybrid flow, the access token would come from the token endpoint after swapping the code (code id_token)
                // or may be a different token if the (code token id_token) is used
                

                // This is optional with "code token" hybrid flow.  But even so, should this not match the access_token that was issued with the id_token? ie that from the token endpoint
                // rather than from the authorization endpoint?
//                if(![self validateHash:(NSString *)[idToken getClaimValueFromPayload:@"at_hash"] forToken:[client getOAuthResponseValueForParameter:kOAuth2ResponseParamAccessToken] usingAlgorithm:idToken.signing_alg]) {
//                    NSLog(@"Access token hash does not match!");
//                    return NO;
//                }

                // For demonstration sake, lets also verify the c_hash
//                if(![self validateHash:(NSString *)[idToken getClaimValueFromPayload:@"c_hash"] forToken:[client getOAuthResponseValueForParameter:kOAuth2ResponseParamCode] usingAlgorithm:idToken.signing_alg]) {
//                    NSLog(@"Code hash does not match!");
//                    return NO;
//                }
            }
            
            NSLog(@"ID Token validation complete");
            return idTokenValid;
            
        } else {
            NSLog(@"Unsupported response_type - Validation failed!");
            return NO;
        }
        
    } else {

        NSLog(@"No ID Token present");
        return YES;
    }
}

+(BOOL) isHybridFlow:(id)response_type
{
    NSArray *clientResponseTypes = [[(NSString *)response_type lowercaseString] componentsSeparatedByString:@" "];
    
    BOOL hasCode = NO;
    BOOL hasToken = NO;
    BOOL hasIdToken = NO;
    
    for(NSString *responseType in clientResponseTypes) {
        if ([responseType isEqualToString:@"code"]) {
            hasCode = YES;
        }
        if ([responseType isEqualToString:@"token"]) {
            hasToken = YES;
        }
        if ([responseType isEqualToString:@"id_token"]) {
            hasIdToken = YES;
        }
    }
    
    // Hybrid is code + token || code + token + id_token || code + id_token
    // so code && (token || id_token)
    
    return hasCode && (hasToken || hasIdToken);
}


+(BOOL) checkValue:(NSString *)expectedValue forKey:(NSString *)key inDictionary:(NSDictionary *)dictionary okayToNotExist:(BOOL)okayToNotExist
{
    BOOL isValidValue = NO;
    
    NSString *valueToCheck = [dictionary objectForKey:key];
    
    if ([valueToCheck length] != 0) {
        if ([valueToCheck isEqualToString:expectedValue]) {
            isValidValue = YES;
        } else {
            isValidValue = NO;
        }
    } else {
        return okayToNotExist;
    }
    
    return isValidValue;
}

+(BOOL)validateAudienceForToken:(JWT *)token Audience:(NSString *)expectedAudience
{
    BOOL isValid = NO;
    // Audience validation rules (OpenID Connect Core section 3.1.3.7)
    
    //    The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer identified by the iss (issuer) Claim as an audience. The aud (audience) Claim MAY contain an array with more than one element. The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience, or if it contains additional audiences not trusted by the Client.
    //    If the ID Token contains multiple audiences, the Client SHOULD verify that an azp Claim is present.
    //    If an azp (authorized party) Claim is present, the Client SHOULD verify that its client_id is the Claim Value.
    
    if ([[token getClaimValueFromPayload:@"aud"] isKindOfClass:[NSArray class]])
    {
        // we have multiple audiences
        for (NSString *thisAudience in [token getClaimValueFromPayload:@"aud"])
        {
            if ([thisAudience isEqualToString:expectedAudience])
            {
                // audience is there and matches
                isValid = YES;
            }
        }
        
        if ([self checkValue:expectedAudience forKey:@"azp" inDictionary:[token getPayload] okayToNotExist:NO]) { // Should this be OKAY if it doesn't exist?
            // audience is there and matches
            isValid = YES;
        }
        
    } else {
        if ([self checkValue:expectedAudience forKey:@"aud" inDictionary:[token getPayload] okayToNotExist:NO]) {
            // audience is there and matches
            isValid = YES;
        }
    }
    
    return isValid;
}

+(BOOL)checkTimeIsSameOrEarlierForClaim:(NSString *)claimName inToken:(JWT *)token skewSeconds:(double)skew
{
    BOOL isSameOrEarlier = NO;
    
    NSDate *claimTimestamp = [NSDate dateWithTimeIntervalSince1970:[[token getClaimValueFromPayload:claimName] doubleValue]];
    NSDate *nowPlusSkew = [[NSDate date] dateByAddingTimeInterval:skew];
    
    if ([claimTimestamp compare:nowPlusSkew] != NSOrderedAscending) {
        isSameOrEarlier = YES;
    }
    return isSameOrEarlier;
}

+(BOOL)validateTimeClaimForToken:(JWT *)token Claim:(NSString *)claimName skewSeconds:(double)skew
{
    if ([self checkTimeIsSameOrEarlierForClaim:claimName inToken:token skewSeconds:skew]) {
        // value is before nowPlusSkew - so is in range
        return YES;
    }

    return NO;
}

+(BOOL)validateHash:(NSString *)hashValue forToken:(NSString *)tokenValue usingAlgorithm:(NSString *)alg
{
    // Where "token" is access_token for at_hash and code for c_hash
    
    if (hashValue != nil)
    {
        NSData *hash = [Utils base64UrlDecodeString:hashValue];
        NSData *left_most_half = [[NSData alloc] init];
        
        if ([alg isEqualToString:@"None"])
        {
            // What do we do here?
            NSLog(@"The signing algorithm is None.  What size hash?");
        } else {
            NSInteger SHA_Digest_Length = [[alg substringFromIndex:2] integerValue]; // remove the first two char (RS / ES / HS) to get the hash length
            SHA *token_sha_hash = [[SHA alloc] initWithData:[tokenValue dataUsingEncoding:NSASCIIStringEncoding] andDigestLength:SHA_Digest_Length];
            NSMutableData *tokenHash = [[NSMutableData alloc] initWithData:[token_sha_hash getHashBytes]];
            
            left_most_half = [tokenHash subdataWithRange:NSMakeRange(0, ([tokenHash length]/2))];
        }
        
        if ([hash isEqualToData:left_most_half]) {
            return YES;
        } else {
            return NO;
        }
    } else {
        NSLog(@"Missing hash value");
        return NO;
    }
    
    return NO;
}

@end
