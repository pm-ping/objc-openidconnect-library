//
//  TokenValidationResult.m
//  Copyright (c) 2014 Ping Identity. All rights reserved.
//

#import "TokenValidationResult.h"

@implementation TokenValidationResult

-(id)initWithTitle:(NSString *)title Detail:(NSString *)detail Result:(JWTValidationResult)result {
    
    self = [super init];
    
    if(self) {
        _ValidationStepTitle = title;
        _ValidationStepDetail = detail;
        _ValidationStepResult = result;
    }

    return self;
}

@end
