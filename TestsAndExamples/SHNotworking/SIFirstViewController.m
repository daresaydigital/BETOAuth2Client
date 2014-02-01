//
//  SIFirstViewController.m
//  SINotworking
//
//  Created by Seivan Heidari on 2013-10-29.
//  Copyright (c) 2013 Seivan Heidari. All rights reserved.
//

#import "SIFirstViewController.h"
#import <SIOAuth2Client.h>
#import <SIHTTPCore.h>

#define CLIENT_ID  @"7y7gp0495bt7acqbqdaw7y7gp0495bt7"
#define APP_SECRET @"ckm6ssv30cwz1zg7xu2pckm6ssv30cwz1zg7xu2p"
#define REDIRECT_URI @"etalio7y7gp0495bt7acqbqdaw7y7gp0495bt7://authentication"



@interface SIFirstViewController ()

@end

@implementation SIFirstViewController

-(void)viewWillAppear:(BOOL)animated;{
  [super viewWillAppear:animated];
  
//  [[[NSURLSession SI_buildSessionWithName:@"x" withBaseURLString:@"http://localhost:3000" andSessionConfiguration:[NSURLSessionConfiguration defaultSessionConfiguration] andRequestSerializer:SIURLSessionRequestSerializerFormURLEncoding.new andResponseSerializer:nil operationQueue:nil] SI_taskPOSTResource:@"users" withParams:@{@"user" : @{@"name" : @[@"has", @"an", @"array"]}} completeBlock:^(NSError *error, NSDictionary *responseObject, NSHTTPURLResponse *urlResponse, NSURLSessionTask *task) {
//    NSLog(@"%@ %@", error, responseObject);
//
//  }] resume];
  
  
  SIOAuth2Client * authClient = [SIOAuth2Client OAuth2ClientWithIdentifier:@"https://api-etalio.3fs.si"
                                                                    baseURL:@"https://api-etalio.3fs.si"
                                                                  clientId:CLIENT_ID
                                                                 secretKey:APP_SECRET
                                                               redirectURI:REDIRECT_URI
                                                                withScopes:@[@"profile.w"]
                                                               requestType:SIORequestEncodingTypeFormURLEncoding];
  
[authClient authenticateWithResourceOwner:@"+46728880188" andPassword:@"diablo" andTokenPath:@"oauth2/token" onComplete:^(SIOAccessCredential *credential, NSError *error) {
  [authClient refreshWithTokenPath:@"oauth2/token" onComplete:^(SIOAccessCredential * newCredential, NSError *yerror) {
    
  }];

}];
  
  
//  [authClient authenticateWithAuthorizationPath:@"oauth2"
//                                   andTokenPath:@"oauth2/token"
//                                     onComplete:^(SIOAccessCredential *oldCredential, NSError *xerror) {
//
//                                       [authClient refreshWithTokenPath:@"oauth2/token" onComplete:^(SIOAccessCredential * newCredential, NSError *yerror) {
//                                         
//                                       }];
//                                     
//
//                                     }];
//  
}

@end

