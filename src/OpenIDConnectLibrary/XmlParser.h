//
//  XmlParser.h
//  Copyright (c) 2014 Paul Meyer. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface XmlParser : NSObject <NSXMLParserDelegate>

@property (weak, nonatomic) NSMutableDictionary *xmlElements;

-(BOOL)parseDocument:(NSData *)xmlData;
-(BOOL)parseDocument:(NSString *)xmlString encoding:(NSStringEncoding)encoding;

@end
