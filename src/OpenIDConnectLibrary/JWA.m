//
//  JWA.m
//  Copyright (c) 2014 Ping Identity. All rights reserved.
//

#import "JWA.h"
#import "JWK.h"
#import "JWT.h"

@implementation JWA

#pragma mark Static Methods

+(JWAAlgorithm)getAlgorithmType:(JWT *)jwt {

    return [self algorithmStringToEnum:[jwt getClaimValueFromHeader:@"alg"]];
}

+(NSString *)algorithmEnumToString:(JWAAlgorithm)enumValue
{
    NSArray *algorithmArray = [[NSArray alloc] initWithObjects:JWAAlgorithmArray];
    return [algorithmArray objectAtIndex:enumValue];
}

+(JWAAlgorithm) algorithmStringToEnum:(NSString*)stringValue
{
    NSArray *algorithmArray = [[NSArray alloc] initWithObjects:JWAAlgorithmArray];
    NSUInteger n = [algorithmArray indexOfObject:stringValue];
    if(n < 1) n = kJWAAlgorithmNone;
    return (JWAAlgorithm) n;
}

@end
