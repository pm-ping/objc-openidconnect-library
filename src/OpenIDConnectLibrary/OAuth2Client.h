//
//  OAuth2Client.h
//  Copyright (c) 2013 Ping Identity. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface OAuth2Client : NSObject {
    NSMutableDictionary *responseData;
    NSMutableDictionary *requestParameters;
}

typedef enum OAuth2RequestTypes {
    kOAuth2RequestTypeAuthorizationCode = 0,
    kOAuth2RequestTypeImplicit,
    kOAuth2RequestTypeResourceOwnerPasswordCredentials,
    kOAuth2RequestTypeClientCredentials,
    kOAuth2RequestTypeExtension,
    kOAuth2RequestTypeAuthorizationCodeExchange,
    kOAuth2RequestTypeResourceServerValidate,
    kOAuth2RequestTypeRefreshToken,
    kOAuth2RequestTypeOIDCBasicClientProfile,
    kOAuth2RequestTypeOIDCBasicClientProfileCodeExchange,
    kOAuth2RequestTypeOIDCImplicitClientProfile,
    kOAuth2RequestTypeOIDCHybridClientProfile
} OAuth2RequestType;

typedef enum OAuth2RequestParameters {
    kOAuth2RequestParamClientId = 0,
    kOAuth2RequestParamClientSecret,
    kOAuth2RequestParamResponseType,
    kOAuth2RequestParamGrantType,
    kOAuth2RequestParamAcrValues,
    kOAuth2RequestParamScope,
    kOAuth2RequestParamIdp,
    kOAuth2RequestParamPfidpadapterid,
    kOAuth2RequestParamNonce,
    kOAuth2RequestParamRedirectUri,
    kOAuth2RequestParamUsername,
    kOAuth2RequestParamPassword,
    kOAuth2RequestParamCode,
    kOAuth2RequestParamState,
    kOAuth2RequestParamPrompt,
    kOAuth2RequestParamValidatorId,
    kOAuth2RequestParamAssertion,
    kOAuth2RequestParamToken,
    kOAuth2RequestParamRefreshToken
} OAuth2RequestParameter;

#define OAuth2RequestParameterArray @"client_id", @"client_secret", @"response_type", @"grant_type", @"acr_values", @"scope", @"idp", @"pfidpadapterid", @"nonce", @"redirect_uri", @"username", @"password", @"code", @"state", @"prompt",@"validator_id", @"assertion", @"token", @"refresh_token", nil

typedef enum OAuth2ResponseParameters {
    kOAuth2ResponseParamAccessToken = 0,
    kOAuth2ResponseParamRefreshToken,
    kOAuth2ResponseParamTokenType,
    kOAuth2ResponseParamExpiresIn,
    kOAuth2ResponseParamCode,
    kOAuth2ResponseParamState,
    kOAuth2ResponseParamError,
    kOAuth2ResponseParamErrorDescription,
    kOAuth2ResponseParamErrorUri,
    kOAuth2ResponseParamIdToken
} OAuth2ResponseParameter;

#define OAuth2ResponseParameterArray @"access_token", @"refresh_token", @"token_type", @"expires_in", @"code", @"state", @"error", @"error_description", @"error_uri", @"id_token", nil


@property (nonatomic, retain) NSString *baseUrl;
@property (nonatomic, retain) NSString *authorizationEndpoint;
@property (nonatomic, retain) NSString *tokenEndpoint;
@property (nonatomic, retain) OAuth2Client *associatedRequest;
@property (nonatomic) OAuth2RequestType requestType;

-(id)init;
-(void)reset;
-(NSString *)description;

// Conversion from Enum to String and back
+(OAuth2ResponseParameter) responseParameterStringToEnum:(NSString*)stringValue;
+(NSString *)responseParameterEnumToString:(OAuth2ResponseParameter)enumValue;
+(OAuth2RequestParameter) requestParameterStringToEnum:(NSString*)stringValue;
+(NSString *)requestParameterEnumToString:(OAuth2RequestParameter)enumValue;

// Error handling
-(BOOL)didSucceed;
-(BOOL)didFail;

// Get / Set Request parameters
-(BOOL)OAuthRequestParameterExists:(OAuth2RequestParameter)parameter;
-(id)getOAuthRequestParameter:(OAuth2RequestParameter)parameter;
-(NSString *)getOAuthRequestParameters;
-(NSString *)getOAuthRequestParameterByName:(NSString *)parameterName;
-(void)setOAuthRequestParameter:(OAuth2RequestParameter)parameter value:(id)value;
-(void)setOAuthRequestParameters:(NSDictionary *)parameters;
-(OAuth2RequestType)getOAuthRequestType;
-(void)setOAuthRequestType:(OAuth2RequestType)type;

// Get response values
-(NSDictionary *)getResponseValues;
-(id)getOAuthResponseValueForParameter:(OAuth2ResponseParameter)parameter;
-(BOOL)OAuthResponseParameterExists:(OAuth2ResponseParameter)parameter;

// Execute OAuth Client actions
-(BOOL)validateAccessToken;
-(BOOL)refreshToken;
-(BOOL)swapCodeForToken;
-(NSString *)buildAuthorizationRedirectUrl;
-(void)callTokenEndpoint;
-(void)callTokenEndpointWithPostData:(NSString *)postData;
-(void)processCallback:(NSString *)urlComponent;
-(void)handleHybridTokens;

@end
