//
//  SIFirstViewController.m
//  SINotworking
//
//  Created by Seivan Heidari on 2013-10-29.
//  Copyright (c) 2013 Seivan Heidari. All rights reserved.
//

#import "SIFirstViewController.h"
#import <BETOAuth2Client.h>

//Application   : Etalio iOS SDK Sample App
//KeyName       : Sample iOS
//ClientId      : 4b76d81aea2ac2bcd3d9ebe30eb55834
//Client secret : ae5a7f277e9df81f21265cd584d28f89
//Platform      : ios
//
//BundleId      : com.seivan.Sample
//Redirects:
//etalio4b76d81aea2ac2bcd3d9ebe30eb55834://authentication

//static NSString * const ETALIORedirectURI = @"etalio4b76d81aea2ac2bcd3d9ebe30eb55834495bt7://authentication";
//static NSString * const ETALIOKeyClientId = @"4b76d81aea2ac2bcd3d9ebe30eb55834";
//static NSString * const ETALIOKeyAppSecret = @"ae5a7f277e9df81f21265cd584d28f89";

static NSString * const ETALIORedirectURI = @"etalio33ddb2e59d7b315807ba49975da4199f://authentication";
static NSString * const ETALIOKeyClientId = @"33ddb2e59d7b315807ba49975da4199f";
static NSString * const ETALIOKeyAppSecret = @"955b2c4071dde0014296d0b63d77ee47";

@interface SIFirstViewController ()

@end

@implementation SIFirstViewController

-(void)viewWillAppear:(BOOL)animated;{
  [super viewWillAppear:animated];
  
  
  
  BETOAuth2Client * authClient = [BETOAuth2Client OAuth2ClientWithIdentifier:@"etalio"
                                                                     baseURL:@"https://api.etalio.com"
                                                                    clientId:ETALIOKeyClientId
                                                                   secretKey:ETALIOKeyAppSecret
                                                                 redirectURI:ETALIORedirectURI
                                                                      scopes:nil
                                                                 requestType:BETOAuth2ClientRequestEncodingTypeFormURLEncoding];
  
  
  
  [authClient authenticateWithAuthorizationPath:@"oauth2"
                                      tokenPath:@"oauth2/token"
                                     completion:^(BETOAuth2Credential *oldCredential, NSError *xerror) {
                                       NSLog(@"%@ %@", oldCredential,xerror);
                                       
                                       [authClient refreshWithTokenPath:@"oauth2/token" completion:^(BETOAuth2Credential * newCredential, NSError *yerror) {
                                         NSLog(@"%@ %@", newCredential,yerror);
                                         
                                         [authClient requestWithResourcePath:@"v1/profile/me" parameters:nil HTTPMethod:@"GET" completion:^(NSDictionary *responseObject, NSHTTPURLResponse *URLResponse, NSError *error) {
                                         NSLog(@"%@ %@", responseObject, error);
                                         }];
                                       }];
                                       
                                       
                                     }];
  
}

@end


//[authClient authenticateWithResourceOwner:@"+46728880188" andPassword:@"diablo" andTokenPath:@"oauth2/token" onComplete:^