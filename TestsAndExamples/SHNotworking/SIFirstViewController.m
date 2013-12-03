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
  
  
  SIOAuth2Client * authClient = [SIOAuth2Client OAuth2ClientWithURLBaseURL:@"https://api-etalio.3fs.si"
                                                                  clientId:CLIENT_ID
                                                                 secretKey:APP_SECRET
                                                               redirectURI:REDIRECT_URI
                                                                withScopes:@[@"profile.w"]];
  
  
  
  [authClient authenticateWithAuthorizationPath:@"oauth2"
                                   andTokenPath:@"oauth2/token"
                                     onComplete:^(SIOAccessCredential *credential, NSError *xerror) {
                                       if(xerror) [[[UIAlertView alloc] initWithTitle:xerror.description
                                                                             message:xerror.description
                                                                            delegate:nil
                                                                   cancelButtonTitle:@"OK"
                                                                   otherButtonTitles:nil, nil] show];
                                       
                                       [authClient refreshWithTokenPath:@"oauth2/token" onComplete:^(SIOAccessCredential *credential, NSError *yerror) {
                                         if(yerror) [[[UIAlertView alloc] initWithTitle:yerror.description
                                                                              message:yerror.description
                                                                             delegate:nil
                                                                    cancelButtonTitle:@"OK"
                                                                    otherButtonTitles:nil, nil] show];
                                         
                                         else {
                                           [authClient requestWithResourcePath:@"v1/profile/me" parameters:nil HTTPMethod:@"GET" onComplete:^(NSDictionary *responseObject, NSError *error) {
                                               NSLog(@"ME REQUEST: %@ %@", error, responseObject);
                                           }];
                                           
                                           [authClient requestWithResourcePath:@"v1/profile/me" parameters:@{@"email" : @"asd@asd1.com"} HTTPMethod:@"PUT" onComplete:^(NSDictionary *responseObject, NSError *error) {
                                             NSLog(@"UPDATE ME REQUEST: %@ %@", error, responseObject);
                                           }];
                                           
                                           
                                           
                                           NSString * path = [NSString stringWithFormat:@"v1/profile/%@",@"44591d04-51e4-4701-a502-cfb90bcfe6fa"];
                                           [authClient requestWithResourcePath:path parameters:nil HTTPMethod:@"GET" onComplete:^(NSDictionary *responseObject, NSError *error) {
                                             NSLog(@"ID REQUEST: %@ %@", error, responseObject);
                                           }];
                                           
                                           [authClient requestWithResourcePath:@"v1/profile/me/applications" parameters:nil HTTPMethod:@"GET" onComplete:^(NSDictionary *responseObject, NSError *error) {
                                             NSLog(@"APPS REQUEST: %@ %@", error, responseObject);
                                           }];
                                           
                                           double delayInSeconds = 5.0;
                                           dispatch_time_t popTime = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delayInSeconds * NSEC_PER_SEC));
                                           dispatch_after(popTime, dispatch_get_main_queue(), ^(void){

                                             [authClient requestWithResourcePath:@"oauth2/revoke"
                                                                      parameters:@{@"refresh_token" : credential.refreshToken} HTTPMethod:@"POST" onComplete:^(NSDictionary *responseObject, NSError *error) {
                                               NSLog(@"LOGOUT REQUEST: %@ %@", error, responseObject);
                                                                        [authClient requestWithResourcePath:@"v1/profile/me/" parameters:nil HTTPMethod:@"GET" onComplete:^(NSDictionary *zxresponseObject, NSError *zxerror) {
                                                                          NSLog(@"LOGGED ME REQUEST: %@ %@", zxerror, zxresponseObject);
                                                                        }];

                                             }];
                                             

                                           });
                                           


                                         }

                                         
                                       }];
                                       

                                     }];
  
}

@end

