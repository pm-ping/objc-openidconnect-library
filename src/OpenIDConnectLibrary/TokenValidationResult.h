//
//  TokenValidationResult.h
//  Copyright (c) 2014 Ping Identity. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface TokenValidationResult : NSObject

typedef enum JWTValidationResults {
    kJWTValidationResultSuccess = 0,
    kJWTValidationResultFailure,
    kJWTValidationResultSkipped,
    kJWTValidationResultNotApplicable,
} JWTValidationResult;

@property (strong, nonatomic) NSString *ValidationStepTitle;
@property (strong, nonatomic) NSString *ValidationStepDetail;
@property (nonatomic) JWTValidationResult ValidationStepResult;

-(id)initWithTitle:(NSString *)title Detail:(NSString *)detail Result:(JWTValidationResult)result;

@end
