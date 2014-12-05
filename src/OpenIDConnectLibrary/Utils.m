//
//  Utils.m
//  Copyright (c) 2014 Paul Meyer. All rights reserved.
//

#import "Utils.h"

@implementation Utils

+(NSData *)base64UrlDecodeString:(NSString *)base64EncodedString
{
    NSString *cleanBase64EncodedString = [[[base64EncodedString stringByReplacingOccurrencesOfString:@"\n" withString:@""] stringByReplacingOccurrencesOfString:@"-" withString:@"+"] stringByReplacingOccurrencesOfString:@"_" withString:@"/"];
    
    NSInteger numEqualsNeeded = 4 - ([cleanBase64EncodedString length] % 4);
    if (numEqualsNeeded == 4) { numEqualsNeeded = 0; }
    NSString *padding = [@"" stringByPaddingToLength:numEqualsNeeded withString:@"=" startingAtIndex:0];
    NSString *base64EncodedStringPadded = [NSString stringWithFormat:@"%@%@", cleanBase64EncodedString, padding];
    NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:base64EncodedStringPadded options:kNilOptions];
    
    return decodedData;
}

+(NSString *) base64UrlEncodeData:(NSData *)data
{
    NSString *base64EncodedString = [data base64EncodedStringWithOptions:kNilOptions];
    
    NSString *base64UrlEncodedString = [[[base64EncodedString stringByReplacingOccurrencesOfString:@"+" withString:@"-"] stringByReplacingOccurrencesOfString:@"/" withString:@"_"] stringByReplacingOccurrencesOfString:@"=" withString:@""];
    
    return base64UrlEncodedString;
}

+(NSString *) jsonPrettyPrint:(NSString *)jsonString base64Encoded:(BOOL)base64Encoded
{
    NSData *jsonData = nil;
    
    if (base64Encoded) {
        jsonData = [Utils base64UrlDecodeString:jsonString];
    } else {
        jsonData = [jsonString dataUsingEncoding:NSUTF8StringEncoding];
    }
    
    NSError *error = nil;
    NSDictionary *jsonDictionary = [NSJSONSerialization JSONObjectWithData:jsonData options:kNilOptions error:&error];
    
    NSMutableString *returnString = [[NSMutableString alloc] init];
    
    for (NSString *k in jsonDictionary) {
        
        if ([k isEqualToString:@"exp"] || [k isEqualToString:@"iat"] ) {
            [returnString appendFormat:@"%@: %@ (%@)\r\n", k, [jsonDictionary valueForKey:k], [NSDate dateWithTimeIntervalSince1970:[[jsonDictionary valueForKey:k] doubleValue]]];
        } else {
            [returnString appendFormat:@"%@: %@\r\n", k, [jsonDictionary valueForKey:k]];
        }
    }
    
    return returnString;
}

+(NSString *) jsonPrettyPrint:(NSDictionary *)jsonDictionary
{
    NSMutableString *returnString = [[NSMutableString alloc] init];
    
    
    for (NSString *k in jsonDictionary) {
        
        if ([k isEqualToString:@"exp"] || [k isEqualToString:@"iat"] ) {
            [returnString appendFormat:@"%@: %@ (%@)\r\n", k, [jsonDictionary valueForKey:k], [NSDate dateWithTimeIntervalSince1970:[[jsonDictionary valueForKey:k] doubleValue]]];
        } else {
            [returnString appendFormat:@"%@: %@\r\n", k, [jsonDictionary valueForKey:k]];
        }
    }
    
    return returnString;
}


@end
