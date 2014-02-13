
#import "BETOAuth2Client.h"
#import <BETURLSession.h>
#import "BETURLSessionRequestSerializerFormURLEncoding.h"
#import "BETURLSessionRequestSerializerJSON.h"
#import "BETURLSessionResponseSerializerJSON.h"


@interface BETOAuth2ClientManager : NSObject
@property(nonatomic,strong) NSMutableDictionary * clientMap;
+(instancetype)sharedManager;
-(void)SH_memoryDebugger;

@end

@implementation BETOAuth2ClientManager




#pragma mark - Init & Dealloc
-(instancetype)init; {
  self = [super init];
  if (self) {
    self.clientMap = @{}.mutableCopy;
    //    [self SH_memoryDebugger];
  }
  
  return self;
}


+(instancetype)sharedManager; {
  static BETOAuth2ClientManager *_sharedInstance;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    _sharedInstance = [[BETOAuth2ClientManager alloc] init];
    
  });
  
  return _sharedInstance;
  
}


#pragma mark - Debugger
-(void)SH_memoryDebugger; {
  double delayInSeconds = 2.0;
  dispatch_time_t popTime = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delayInSeconds * NSEC_PER_SEC));
  dispatch_after(popTime, dispatch_get_main_queue(), ^(void){
    
    NSLog(@"MAP %@",self.clientMap);
    
    [self SH_memoryDebugger];
  });
}


@end


@interface BETOAccessCredential ()

+(instancetype)accessCredentialWithDictionary:(NSDictionary *)theDictionary;
@end


@interface BETOAuth2Client ()

@property(nonatomic,copy)   NSString     * baseURLString;
@property(nonatomic,copy)   NSString     * clientId;
@property(nonatomic,copy)   NSString     * secretKey;
@property(nonatomic,copy)   NSArray      * scopes;
@property(nonatomic,copy)   NSString     * redirectURI;
@property(nonatomic,strong) NSURLSession * session;
@property(nonatomic,copy) NSString * authorizationPath;
@property(nonatomic,copy) NSString * tokenPath;
@property(nonatomic,copy) NSString * nonceState;
@property(nonatomic,copy) BETOAuth2ClientAuthenticationCompleteBlock authenticationCompletionBlock;

@end

@implementation BETOAuth2Client : NSObject

#pragma mark - Fetcher
+(instancetype)existingOAuth2ClientWithIdentifier:(NSString *)theIdentifier; {
  NSParameterAssert(theIdentifier);
  BETOAuth2Client * client = [[BETOAuth2ClientManager sharedManager].clientMap objectForKey:theIdentifier];
  NSParameterAssert(client);
  return client;
  
}

#pragma mark - Initializer


+(instancetype)OAuth2ClientWithIdentifier:(NSString *)theIdentifier
                               baseURL:(NSString *)theBaseUrl
                                 clientId:(NSString *)theClientId
                                secretKey:(NSString *)theSecretKey
                              redirectURI:(NSString *)theRedirectURI
                               withScopes:(NSArray *)theScopes
                              requestType:(BETRequestEncodingType)requestType; {
  NSParameterAssert(theIdentifier);
  NSParameterAssert(theBaseUrl);
  NSParameterAssert(theClientId);
  NSParameterAssert(theSecretKey);
  NSParameterAssert(theRedirectURI);
  BETOAuth2Client * client = [[self alloc] init];
  client.scopes = theScopes;
  client.baseURLString = theBaseUrl;
  client.clientId = theClientId;
  client.secretKey = theSecretKey;
  client.redirectURI = theRedirectURI;
  NSURLSessionConfiguration * sessionConfiguration = [NSURLSessionConfiguration defaultSessionConfiguration];
  sessionConfiguration.HTTPCookieAcceptPolicy = NSHTTPCookieAcceptPolicyNever;
  sessionConfiguration.HTTPShouldSetCookies = NO;
  sessionConfiguration.HTTPShouldUsePipelining = NO;
  sessionConfiguration.HTTPCookieStorage = nil;
  sessionConfiguration.URLCache = nil;
  sessionConfiguration.URLCredentialStorage = nil;
  BETURLSessionRequestSerializer * request = nil;
  switch (requestType) {
    case BETRequestEncodingTypeJSON:
      request = [BETURLSessionRequestSerializerJSON new];
      break;
    case BETRequestEncodingTypeFormURLEncoding:
      request = [BETURLSessionRequestSerializerFormURLEncoding new];
    default:
      break;
  }
  
  client.session = [NSURLSession bet_fetchSessionWithName:theIdentifier];
  if(client.session == nil) client.session = [NSURLSession bet_sessionWithName:theIdentifier
                                                            baseURLString:client.baseURLString
                                                      sessionConfiguration:sessionConfiguration
                                                         requestSerializer:request
                                                        responseSerializer:
                                              [BETURLSessionResponseSerializerJSON serializerWithJSONReadingOptions:NSJSONWritingPrettyPrinted withoutNull:YES] operationQueue:nil];
  
  
  [[BETOAuth2ClientManager sharedManager].clientMap setObject:client forKey:theIdentifier];


  
  return client;
  
}


-(void)setAccessCredential:(BETOAccessCredential *)accessCredential; {
  _accessCredential = accessCredential;
  if(accessCredential) [self.session bet_setValue:[NSString stringWithFormat:@"Bearer %@", accessCredential.accessToken] forHTTPHeaderField:@"Authorization"];
  else [self.session bet_setValue:nil forHTTPHeaderField:@"Authorization"];
  
  
}


-(void)authenticateWithResourceOwner:(NSString *)theUsername andPassword:(NSString *)thePassword
                        andTokenPath:(NSString *)theTokenPath
                          onComplete:(BETOAuth2ClientAuthenticationCompleteBlock)theBlock; {
  NSParameterAssert(theBlock);
  NSParameterAssert(theTokenPath);
  NSParameterAssert(theUsername);
  NSParameterAssert(thePassword);
  self.tokenPath = theTokenPath;
  self.session.bet_delegate = (id <NSURLSessionDataDelegate,NSURLSessionDownloadDelegate>)self;
  NSMutableDictionary *     params = @{@"grant_type" : @"password",
                                       @"client_id" : self.clientId,
                                       @"client_secret" : self.secretKey,
                                       @"username" : theUsername,
                                       @"password" : thePassword
                                       }.mutableCopy;
  
  if([theUsername isEqualToString:self.clientId]) params[@"grant_type"] = @"client_credentials";
  

  __weak typeof(self) weakSelf = self;
  self.authenticationCompletionBlock = theBlock;
  NSURLSessionTask * task = [self.session bet_taskPOSTResource:theTokenPath withParams:params completion:^(NSObject<NSFastEnumeration> *responseObject, NSHTTPURLResponse *urlResponse, NSURLSessionTask *task, NSError *error) {
    
    
    weakSelf.accessCredential = [BETOAccessCredential accessCredentialWithDictionary:(NSDictionary *)responseObject];
    weakSelf.authenticationCompletionBlock(weakSelf.accessCredential, error);
    
  }];
  
  
  [task resume];
  
  
  
  
  
}

-(void)authenticateWithAuthorizationPath:(NSString *)theAuthorizationPath andTokenPath:(NSString *)theTokenPath
                              onComplete:(BETOAuth2ClientAuthenticationCompleteBlock)theBlock; {
  NSParameterAssert(theBlock);
  NSParameterAssert(theAuthorizationPath);
  NSParameterAssert(theTokenPath);
  self.authorizationPath = theAuthorizationPath;
  self.tokenPath = theTokenPath;
  CFUUIDRef uuid = CFUUIDCreate(NULL);
  CFStringRef nonce = CFUUIDCreateString(NULL, uuid);
  CFRelease(uuid);
  
  self.nonceState = (NSString *)CFBridgingRelease(nonce);
  NSParameterAssert(self.nonceState);
  
  
  
  NSMutableDictionary * params = @{@"response_type" : @"code",
                                   @"client_id" : self.clientId,
                                   @"redirect_uri" : self.redirectURI,
                                   @"state" : self.nonceState
                                   }.mutableCopy;
  
  if(self.scopes && self.scopes.count > 0) [params addEntriesFromDictionary:@{@"scope" : [self.scopes componentsJoinedByString:@" "]}];
  
  NSURL * requestUrl =[self.session bet_taskGETResource:theAuthorizationPath withParams:params.copy completion:nil].currentRequest.URL;
  self.authenticationCompletionBlock = theBlock;
  [[UIApplication sharedApplication] openURL:requestUrl];
  
}


-(BOOL)handleApplicationOpenURL:(NSURL *)theUrl
          onlyMatchingUrlPrefix:(NSString *)thePrefix
    withSourceApplicationString:(__unused NSString *)theSourceApplicationString; {
  
  NSParameterAssert(theUrl);
  NSParameterAssert(thePrefix);
  NSParameterAssert(theSourceApplicationString);
  
  if(self.authenticationCompletionBlock == nil || [theUrl.absoluteString hasPrefix:thePrefix] == NO)
    return NO;
  
  
  NSMutableDictionary * params = [self.session.bet_serializerForResponse
                                  queryDictionaryFromString:theUrl.query].mutableCopy;
  
  
  if ([params[@"state"] isEqualToString:[self.session.bet_serializerForRequest escapedQueryValueFromString:self.nonceState]] == NO) {
    NSDictionary * userInfo = @{
                                NSLocalizedDescriptionKey:
                                  NSLocalizedStringFromTable(@"state_error", @"BETURLSessionBlocks", nil),
                                
                                NSLocalizedFailureReasonErrorKey:
                                  NSLocalizedStringFromTable(@"The state code does not validate against CRSF protection", @"BETURLSessionBlocks", nil),
                                
                                NSURLErrorFailingURLErrorKey:theUrl
                                };
    
    NSError * error = [[NSError alloc] initWithDomain:NSURLErrorDomain code:NSURLErrorUserCancelledAuthentication userInfo:userInfo];
    self.authenticationCompletionBlock(nil, error);
  }
  
  else if(params[@"error"]) {
    NSDictionary * userInfo = @{
                                NSLocalizedDescriptionKey:
                                  [NSString stringWithFormat:NSLocalizedStringFromTable(@"%@", @"BETURLSessionBlocks", nil), params[@"error"]],
                                NSLocalizedFailureReasonErrorKey:
                                  [NSString stringWithFormat:NSLocalizedStringFromTable(@"%@", @"BETURLSessionBlocks", nil), params[@"error_description"]],
                                NSURLErrorFailingURLErrorKey:theUrl
                                };
    
    NSError * error = [[NSError alloc] initWithDomain:NSURLErrorDomain code:NSURLErrorUserCancelledAuthentication userInfo:userInfo];
    self.authenticationCompletionBlock(nil, error);
  }
  else {
    NSDictionary * postData = @{@"grant_type" : @"authorization_code",
                                @"code" : params[@"code"],
                                @"redirect_uri" : self.redirectURI,
                                @"client_secret" : self.secretKey,
                                @"client_id" : self.clientId
                                };
    
    
    __weak typeof(self) weakSelf = self;
    [[self.session bet_taskPOSTResource:self.tokenPath withParams:postData completion:^(NSObject<NSFastEnumeration> *responseObject, NSHTTPURLResponse *urlResponse, NSURLSessionTask *task, NSError *error) {
      weakSelf.accessCredential = [BETOAccessCredential accessCredentialWithDictionary:(NSDictionary *)responseObject];
      weakSelf.authenticationCompletionBlock(weakSelf.accessCredential, error);
    }] resume];
    
  }
  
  
  return YES;
}


-(void)refreshWithTokenPath:(NSString *)theTokenPath
                 onComplete:(BETOAuth2ClientAuthenticationCompleteBlock)theBlock; {

  NSParameterAssert(self.accessCredential);
  NSParameterAssert(self.accessCredential.refreshToken);
  NSParameterAssert(self.secretKey);
  NSParameterAssert(self.clientId);
  NSParameterAssert(self.session);
  
  
  NSDictionary * postData = @{@"grant_type" : @"refresh_token",
                              @"refresh_token" : self.accessCredential.refreshToken,
                              @"client_secret" : self.secretKey,
                              @"client_id" : self.clientId
                              };
  
  
  __weak typeof(self) weakSelf = self;
  [[self.session bet_taskPOSTResource:theTokenPath withParams:postData completion:^(NSObject<NSFastEnumeration> *responseObject, NSHTTPURLResponse *urlResponse, NSURLSessionTask *task,NSError *error) {
    weakSelf.accessCredential = [BETOAccessCredential accessCredentialWithDictionary:(NSDictionary *)responseObject];
    theBlock(weakSelf.accessCredential, error);
  }] resume];
  
  
}

-(void)requestWithResourcePath:(NSString *)theResourcePath
                    parameters:(NSDictionary *)theParameters
                    HTTPMethod:(NSString *)theHTTPMethod
                    onComplete:(BETOAuth2ClientRequestCompleteBlock)theBlock; {
  
  NSParameterAssert(theHTTPMethod);
  NSParameterAssert(theResourcePath);
  NSParameterAssert(self.session);
  
  [[self.session bet_buildTaskWithHTTPMethodString:theHTTPMethod onResource:theResourcePath params:theParameters completion:^(NSObject<NSFastEnumeration> *responseObject, NSHTTPURLResponse * HTTPURLResponse, NSURLSessionTask *task, NSError *error) {
    if(theBlock) theBlock((NSDictionary *)responseObject, error, HTTPURLResponse);
  }] resume];
  
  
}



@end

