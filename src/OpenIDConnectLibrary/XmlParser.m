//
//  XmlParser.m
//  Copyright (c) 2014 Paul Meyer. All rights reserved.
//

#import "XmlParser.h"

@implementation XmlParser

NSString *currentXmlElement = @"";
NSMutableString *elementValue;
NSMutableDictionary *allValues;

-(BOOL)parseDocument:(NSData *)xmlData {
    
    if (xmlData == nil) {
        return NO;
    }
    
    NSXMLParser *xmlparser = [[NSXMLParser alloc] initWithData:xmlData];
    [xmlparser setDelegate:self];
    [xmlparser setShouldResolveExternalEntities:NO];
    [xmlparser setShouldProcessNamespaces:YES];
    
    if ([xmlparser parse]) {
        return YES;
    }
    
    return NO;
}

-(BOOL)parseDocument:(NSString *)xmlString encoding:(NSStringEncoding)encoding {
    
    return [self parseDocument:[xmlString dataUsingEncoding:encoding]];
}

-(void)parserDidStartDocument:(NSXMLParser *)parser {
    
    NSLog(@"Parsing XML");
    allValues = [[NSMutableDictionary alloc] init];
}

-(void)parserDidEndDocument:(NSXMLParser *)parser {
    
    NSLog(@"Parsing XML Complete");
    _xmlElements = allValues;
}

-(void)parser:(NSXMLParser *)parser didStartElement:(NSString *)elementName namespaceURI:(NSString *)namespaceURI qualifiedName:(NSString *)qName attributes:(NSDictionary *)attributeDict {
    
    NSLog(@"Parsing element: %@", elementName);
    currentXmlElement = elementName;
    elementValue = [[NSMutableString alloc] init];
}

- (void)parser:(NSXMLParser *)parser foundCharacters:(NSString *)string {
    
    [elementValue appendString:string];
}

- (void)parser:(NSXMLParser *)parser foundIgnorableWhitespace:(NSString *)whitespaceString {
    
    NSLog(@"ignoring whitespace...");
}

-(void)parser:(NSXMLParser *)parser didEndElement:(NSString *)elementName namespaceURI:(NSString *)namespaceURI qualifiedName:(NSString *)qName {
    
    NSLog(@"Parsed element (%@): %@", currentXmlElement, elementValue);
    [allValues setValue:elementValue forKey:currentXmlElement];
}


// error handling
-(void)parser:(NSXMLParser *)parser parseErrorOccurred:(NSError *)parseError {
    NSLog(@"XMLParser error: %@", [parseError localizedDescription]);
}

-(void)parser:(NSXMLParser *)parser validationErrorOccurred:(NSError *)validationError {
    NSLog(@"XMLParser error: %@", [validationError localizedDescription]);
}

@end
