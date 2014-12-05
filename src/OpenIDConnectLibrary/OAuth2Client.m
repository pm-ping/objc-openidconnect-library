//
//  OAuth2Client.m
//  Copyright (c) 2013 Ping Identity. All rights reserved.
//

#import "OAuth2Client.h"
#import "HttpHelper.h"

@implementation OAuth2Client

-(id)init {
    
    if (self = [super init]) {

        _baseUrl = @"";
        _tokenEndpoint = @"/as/token.oauth2";
        _authorizationEndpoint = @"/as/authorization.oauth2";

        responseData = [[NSMutableDictionary alloc] init];
        requestParameters = [[NSMutableDictionary alloc] init];
        
        return self;
    }
    
    return nil;
}

-(void)reset {
    
    _baseUrl = @"";
    _tokenEndpoint = @"/as/token.oauth2";
    _authorizationEndpoint = @"/as/authorization.oauth2";

    [requestParameters removeAllObjects];
    [responseData removeAllObjects];
}

+(NSString *)requestParameterEnumToString:(OAuth2RequestParameter)enumValue
{
    NSArray *parameterArray = [[NSArray alloc] initWithObjects:OAuth2RequestParameterArray];
    return [parameterArray objectAtIndex:enumValue];
}

+(OAuth2RequestParameter) requestParameterStringToEnum:(NSString*)stringValue
{
    NSArray *parameterArray = [[NSArray alloc] initWithObjects:OAuth2RequestParameterArray];
    NSUInteger n = [parameterArray indexOfObject:stringValue];
    if(n < 1) n = kOAuth2RequestParamClientId;
    return (OAuth2RequestParameter) n;
}

+(NSString *)responseParameterEnumToString:(OAuth2ResponseParameter)enumValue
{
    NSArray *parameterArray = [[NSArray alloc] initWithObjects:OAuth2ResponseParameterArray];
    return [parameterArray objectAtIndex:enumValue];
}

+(OAuth2ResponseParameter) responseParameterStringToEnum:(NSString*)stringValue
{
    NSArray *parameterArray = [[NSArray alloc] initWithObjects:OAuth2ResponseParameterArray];
    NSUInteger n = [parameterArray indexOfObject:stringValue];
    if(n < 1) n = kOAuth2ResponseParamAccessToken;
    return (OAuth2ResponseParameter) n;
}

-(OAuth2RequestType)getOAuthRequestType {
    
    return _requestType;
}

-(void)setOAuthRequestType:(OAuth2RequestType)type {

    _requestType = type;
}

-(void)setOAuthRequestParameters:(NSDictionary *)parameters {

    [requestParameters removeAllObjects];
    [requestParameters addEntriesFromDictionary:parameters];
}

-(void)setOAuthRequestParameter:(OAuth2RequestParameter)parameter value:(id)value
{
    if (value != nil)
    {
        if ([value isKindOfClass:[NSString class]])
        {
            if (![value isEqualToString:@""])
            {
                [requestParameters setValue:value forKey:[OAuth2Client requestParameterEnumToString:parameter]];
            }
        } else             {
            [requestParameters setValue:value forKey:[OAuth2Client requestParameterEnumToString:parameter]];
        }
        
    }
}

-(id)getOAuthRequestParameterByName:(NSString *)parameter
{
    return [requestParameters objectForKey:parameter];
}

-(id)getOAuthRequestParameter:(OAuth2RequestParameter)parameter
{
    return [requestParameters objectForKey:[OAuth2Client requestParameterEnumToString:parameter]];
}

-(NSDictionary *)getOAuthRequestParameters
{
    return requestParameters;
}

-(BOOL)OAuthRequestParameterExists:(OAuth2RequestParameter)parameter
{
    return [requestParameters objectForKey:[OAuth2Client requestParameterEnumToString:parameter]] != nil;
}

-(NSDictionary *)getResponseValues {

    return responseData;
}

-(id)getOAuthResponseValueForParameter:(OAuth2ResponseParameter)parameter
{
    return [responseData objectForKey:[OAuth2Client responseParameterEnumToString:parameter]];
}

-(BOOL)OAuthResponseParameterExists:(OAuth2ResponseParameter)parameter
{
    return [responseData objectForKey:[OAuth2Client responseParameterEnumToString:parameter]] != nil;
}

-(void)handleHybridTokens
{
//    [self setOAuthParameter:kOAuth2RequestParamInitialAccessToken value:[self getOAuthParameter:kOAuth2RequestParamAccessToken]];
//    [self setOAuthParameter:kOAuth2RequestParamInitialIdToken value:[self getOAuthParameter:kOAuth2RequestParamIdToken]];
}

-(BOOL)validateAccessToken
{
    if ([self getOAuthRequestParameter:kOAuth2RequestParamToken] != nil)
    {
        [self setOAuthRequestParameter:kOAuth2RequestParamGrantType value:@"urn:pingidentity.com:oauth2:grant_type:validate_bearer"];
        [self callTokenEndpointWithPostData:[self buildTokenEndpointPostData]];

        return [self didSucceed];
    }
    
    return NO;
}

-(BOOL)refreshToken
{
    if ([self getOAuthRequestParameter:kOAuth2RequestParamRefreshToken] != nil)
    {
        [self setOAuthRequestParameter:kOAuth2RequestParamGrantType value:@"refresh_token"];
        [self callTokenEndpointWithPostData:[self buildTokenEndpointPostDataForRefreshToken]];
        
        return [self didSucceed];
    }
    
    return NO;
}

-(BOOL)swapCodeForToken
{
    if ([self getOAuthResponseValueForParameter:kOAuth2ResponseParamCode] != nil)
    {
        [self setOAuthRequestParameter:kOAuth2RequestParamGrantType value:@"authorization_code"];
        [self setOAuthRequestParameter:kOAuth2RequestParamCode value:[self getOAuthResponseValueForParameter:kOAuth2ResponseParamCode]];
        [self callTokenEndpoint];
        
        return [self didSucceed];
    }
    
    return NO;
}

-(NSString *)getTokenEndpointUrl
{
    if ([_tokenEndpoint hasPrefix:@"/"]) {
        return [NSString stringWithFormat:@"%@%@", _baseUrl, _tokenEndpoint];
    } else {
        return [NSString stringWithFormat:@"%@", _tokenEndpoint];
    }
}

-(NSString *)getAuthorizationEndpointUrl
{
    if ([_authorizationEndpoint hasPrefix:@"/"]) {
        return [NSString stringWithFormat:@"%@%@", _baseUrl, _authorizationEndpoint];
    } else {
        return [NSString stringWithFormat:@"%@", _authorizationEndpoint];
    }
}

-(NSString *)getAuthorizationHeader:(NSString *)withAccessToken
{
    return [NSString stringWithFormat:@"Bearer %@", withAccessToken];
}

-(NSString *)appendOAuthRequestParameter:(OAuth2RequestParameter)parameter
{
    if ([self OAuthRequestParameterExists:parameter]) {
        return [NSString stringWithFormat:@"&%@=%@", [OAuth2Client requestParameterEnumToString:parameter], [[self getOAuthRequestParameter:parameter]stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding]];
    }
    
    return @"";
}

-(NSString *)buildAuthorizationRedirectUrl
{
    // Uses the values in the current operation to build an AuthZ url
    NSMutableString *authenticationUrl = [NSMutableString stringWithString:[self getAuthorizationEndpointUrl]];

    // Add required values:
    [authenticationUrl appendFormat:@"?client_id=%@", [self getOAuthRequestParameter:kOAuth2RequestParamClientId]];
    [authenticationUrl appendString:[self appendOAuthRequestParameter:kOAuth2RequestParamResponseType]];
    [authenticationUrl appendString:[self appendOAuthRequestParameter:kOAuth2RequestParamRedirectUri]];
    [authenticationUrl appendString:[self appendOAuthRequestParameter:kOAuth2RequestParamScope]];
    [authenticationUrl appendString:[self appendOAuthRequestParameter:kOAuth2RequestParamNonce]];
    [authenticationUrl appendString:[self appendOAuthRequestParameter:kOAuth2RequestParamState]];
    [authenticationUrl appendString:[self appendOAuthRequestParameter:kOAuth2RequestParamPrompt]];
    [authenticationUrl appendString:[self appendOAuthRequestParameter:kOAuth2RequestParamIdp]];
    [authenticationUrl appendString:[self appendOAuthRequestParameter:kOAuth2RequestParamAcrValues]];
    [authenticationUrl appendString:[self appendOAuthRequestParameter:kOAuth2RequestParamPfidpadapterid]];
    
    return [NSString stringWithString:authenticationUrl];
}

- (NSString *) buildTokenEndpointPostData
{
    NSMutableString *tokenUrl = [NSMutableString stringWithFormat:@"grant_type=%@", [[self getOAuthRequestParameter:kOAuth2RequestParamGrantType] stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding]];
    
    [tokenUrl appendString:[self appendOAuthRequestParameter:kOAuth2RequestParamClientId]];
    [tokenUrl appendString:[self appendOAuthRequestParameter:kOAuth2RequestParamClientSecret]];
    [tokenUrl appendString:[self appendOAuthRequestParameter:kOAuth2RequestParamCode]];
    [tokenUrl appendString:[self appendOAuthRequestParameter:kOAuth2RequestParamRedirectUri]];
    [tokenUrl appendString:[self appendOAuthRequestParameter:kOAuth2RequestParamRefreshToken]];
    [tokenUrl appendString:[self appendOAuthRequestParameter:kOAuth2RequestParamUsername]];
    [tokenUrl appendString:[self appendOAuthRequestParameter:kOAuth2RequestParamPassword]];
    [tokenUrl appendString:[self appendOAuthRequestParameter:kOAuth2RequestParamScope]];
    [tokenUrl appendString:[self appendOAuthRequestParameter:kOAuth2RequestParamAssertion]];
    [tokenUrl appendString:[self appendOAuthRequestParameter:kOAuth2RequestParamToken]];
    
    return [NSString stringWithString:tokenUrl];
}

- (NSString *) buildTokenEndpointPostDataForRefreshToken
{
    NSMutableString *tokenUrl = [NSMutableString stringWithFormat:@"grant_type=%@", [[self getOAuthRequestParameter:kOAuth2RequestParamGrantType] stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding]];
    
    [tokenUrl appendString:[self appendOAuthRequestParameter:kOAuth2RequestParamClientId]];
    [tokenUrl appendString:[self appendOAuthRequestParameter:kOAuth2RequestParamClientSecret]];
    [tokenUrl appendString:[self appendOAuthRequestParameter:kOAuth2RequestParamRefreshToken]];
    
    return [NSString stringWithString:tokenUrl];
}

- (NSString *) buildTokenEndpointPostDataForValidateBearer
{
    NSMutableString *tokenUrl = [NSMutableString stringWithFormat:@"grant_type=%@", [[self getOAuthRequestParameter:kOAuth2RequestParamGrantType] stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding]];
    
    [tokenUrl appendString:[self appendOAuthRequestParameter:kOAuth2RequestParamClientId]];
    [tokenUrl appendString:[self appendOAuthRequestParameter:kOAuth2RequestParamClientSecret]];
    [tokenUrl appendString:[self appendOAuthRequestParameter:kOAuth2RequestParamToken]];
    
    return [NSString stringWithString:tokenUrl];
}

-(void)callTokenEndpoint
{
    NSString *postData = [self buildTokenEndpointPostData];
    [self callTokenEndpointWithPostData:postData];
}

-(void)callTokenEndpointWithPostData:(NSString *)postData
{
    NSString *tokenEndpoint = [self getTokenEndpointUrl];
    HttpResponse *postResponse = [HttpHelper postToUrl:tokenEndpoint withPostData:postData];

    NSError *error = nil;
    NSLog(@"Response data: %@", [[NSString alloc] initWithData:postResponse.responseData encoding:NSUTF8StringEncoding]);
    
    // We should probably pre-check that it's JSON....
    NSDictionary* jsonResponse = [NSJSONSerialization JSONObjectWithData:postResponse.responseData options:kNilOptions error:&error];
    
    [responseData removeAllObjects];
    [responseData addEntriesFromDictionary:jsonResponse];
}

-(void)processCallback:(NSString *)urlComponent
{
    NSMutableDictionary *urlParams = [[NSMutableDictionary alloc] init];

    for (NSString *param in [urlComponent componentsSeparatedByString:@"&"]) {
        NSArray *qsElements = [param componentsSeparatedByString:@"="];
        if([qsElements count] < 2) continue;
        [urlParams setObject:[qsElements objectAtIndex:1] forKey:[qsElements objectAtIndex:0]];
    };
    
    [responseData removeAllObjects];
    [responseData addEntriesFromDictionary:urlParams];
}

-(BOOL)didSucceed {
    
    return ![self OAuthResponseParameterExists:kOAuth2ResponseParamError];
}

-(BOOL)didFail {
    
    return [self OAuthResponseParameterExists:kOAuth2ResponseParamError];
}

-(NSString *)description {

    NSMutableString *thisDescription = [[NSMutableString alloc] init];

    [thisDescription appendString:@"OAuth 2.0 Client"];
    
    for (NSString *param in [requestParameters allKeys]) {
        [thisDescription appendString:[NSString stringWithFormat:@"\n : %@ = %@", param, [requestParameters objectForKey:param]]];
    }
    return thisDescription;
}

@end
