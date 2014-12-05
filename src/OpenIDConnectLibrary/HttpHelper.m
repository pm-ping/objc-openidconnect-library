//
//  HttpHelper.m
//  Copyright (c) 2013 Ping Identity. All rights reserved.
//

#import "HttpHelper.h"
#import "HttpResponse.h"
#import "HttpIgnoreSSLErrors.h"


@implementation HttpHelper

NSURLConnection *c;
NSTimer *HttpTimeout;

+ (HttpResponse *) postToUrl:(NSString *)url withPostData:(NSString *)postData
{
    return [self postToUrl:url withPostData:postData withContentType:nil];
}

+ (HttpResponse *) postToUrl:(NSString *)url withPostData:(NSString *)postData withContentType:(NSString *)contentType
{
    NSLog(@"Contacting URL: %@", url);
    NSLog(@"Request body (POST data): %@", postData);
    
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] init];
    [request setURL:[NSURL URLWithString:[NSString stringWithFormat:@"%@", url]]];
    [request setHTTPMethod:@"POST"];
    [request setHTTPBody:[postData dataUsingEncoding:NSUTF8StringEncoding]];
    [request setCachePolicy:NSURLRequestReloadIgnoringLocalCacheData];
    [request setTimeoutInterval:10];
    if (contentType != nil) {
        [request setValue:contentType forHTTPHeaderField:@"Content-Type"];
    }
    
    // *** Set a 10 second timeout for the Http call
    HttpTimeout = [NSTimer scheduledTimerWithTimeInterval:10 target:self selector:@selector(timeoutExpired:) userInfo:nil repeats:NO];
    
    // *** Ignore SSL Certificate errors that are likely in a test environment.  DO NOT USE THIS IN PRODUCTION!
    HttpIgnoreSSLErrors *ignoreSSL = [[HttpIgnoreSSLErrors alloc] init];
    c = [[NSURLConnection alloc] initWithRequest:request delegate:ignoreSSL startImmediately:NO];
    [c setDelegateQueue:[[NSOperationQueue alloc] init]];
    [c start];

    HttpResponse *httpResponse = [[HttpResponse alloc] init];
    [httpResponse setResponseData:[ignoreSSL getData]];
    [httpResponse setResponseCode:[ignoreSSL responseCode]];
    
    return httpResponse;
}

+(HttpResponse *)getUrl:(NSString *)url withAuthZHeader:(NSString *)authZHeader
{
    NSLog(@"Contacting URL: %@", url);
    
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] init];
    [request setURL:[NSURL URLWithString:[NSString stringWithFormat:@"%@", url]]];
    if (authZHeader != nil) {
        NSLog(@"Using Authorization header: %@", authZHeader);
        [request addValue:authZHeader forHTTPHeaderField:@"Authorization"];
    }
    [request setHTTPMethod:@"GET"];
    [request setCachePolicy:NSURLRequestReloadIgnoringLocalCacheData];
    [request setTimeoutInterval:10];
    
    // *** Set a 10 second timeout for the Http call
    HttpTimeout = [NSTimer scheduledTimerWithTimeInterval:10 target:self selector:@selector(timeoutExpired:) userInfo:nil repeats:NO];
    
    // *** Ignore SSL Certificate errors that are likely in a test environment.  DO NOT USE THIS IN PRODUCTION!
    HttpIgnoreSSLErrors *ignoreSSL = [[HttpIgnoreSSLErrors alloc] init];
    c = [[NSURLConnection alloc] initWithRequest:request delegate:ignoreSSL startImmediately:NO];
    [c setDelegateQueue:[[NSOperationQueue alloc] init]];
    [c start];
    
    HttpResponse *httpResponse = [[HttpResponse alloc] init];
    [httpResponse setResponseData:[ignoreSSL getData]];
    [httpResponse setResponseCode:[ignoreSSL responseCode]];
    
    return httpResponse;
}


+(void)timeoutExpired:(NSTimer *)timer
{
    if (c != nil) {
        [c cancel];
    }
}

@end
