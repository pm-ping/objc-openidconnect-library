//
//  HttpIgnoreSSLErrors.m
//  Copyright (c) 2013 Ping Identity. All rights reserved.
//

#import "HttpIgnoreSSLErrors.h"

@implementation HttpIgnoreSSLErrors

@synthesize dataDownloaded = _dataDownloaded;
@synthesize downloaded = _downloaded;
@synthesize responseCode = _responseCode;

-(id)init{
    self = [super init];
    if (self) {
        _dataDownloaded = nil;
        _downloaded = [[NSCondition alloc] init];
    }
    return self;
}

- (BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace {
    return [protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust];
}

- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    [challenge.sender useCredential:[NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust] forAuthenticationChallenge:challenge];
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection {
}

- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response {
    
    NSHTTPURLResponse *HttpResponse = (NSHTTPURLResponse *)response;
    _responseCode = [HttpResponse statusCode];
}

-(void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error {
}

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data {
    _dataDownloaded = data;
    [_downloaded lock];
    [_downloaded signal];
    [_downloaded unlock];
}

-(NSData *)getData {
    if (!_dataDownloaded){
        [_downloaded lock];
        [_downloaded wait];
        [_downloaded unlock];
    }
    return _dataDownloaded;
}

@end
