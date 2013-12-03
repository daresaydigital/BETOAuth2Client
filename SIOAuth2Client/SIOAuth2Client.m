
#import "SIOAuth2Client.h"
#import <SIHTTPCore.h>


@interface SIOAuth2ClientManager : NSObject
@property(nonatomic,strong) NSMutableDictionary * clientMap;
+(instancetype)sharedManager;
-(void)SH_memoryDebugger;

@end

@implementation SIOAuth2ClientManager




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
  static SIOAuth2ClientManager *_sharedInstance;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    _sharedInstance = [[SIOAuth2ClientManager alloc] init];
    
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


@interface SIOAccessCredential ()
+(instancetype)accessCredentialWithDictionary:(NSDictionary *)theDictionary;
@end


@interface SIOAuth2Client ()
@property(nonatomic,copy)   NSString     * baseURLString;
@property(nonatomic,copy)   NSString     * clientId;
@property(nonatomic,copy)   NSString     * secretKey;
@property(nonatomic,copy)   NSArray      * scopes;
@property(nonatomic,copy)   NSString     * redirectURI;
@property(nonatomic,strong) NSURLSession * session;
@property(nonatomic,copy) NSString * authorizationPath;
@property(nonatomic,copy) NSString * tokenPath;
@property(nonatomic,copy) NSString * nonceState;
@property(nonatomic,copy) SIOAuth2ClientAuthenticationCompleteBlock authenticationCompletionBlock;

@end

@implementation SIOAuth2Client : NSObject

#pragma mark - Fetcher
+(instancetype)fetchOAuth2ClientWithURLBaseURL:(NSString *)theBaseUrl; {
  NSParameterAssert(theBaseUrl);
  SIOAuth2Client * client = [[SIOAuth2ClientManager sharedManager].clientMap objectForKey:theBaseUrl];
  NSParameterAssert(client);
  return client;
  
}

#pragma mark - Initializer
+(instancetype)OAuth2ClientWithURLBaseURL:(NSString *)theBaseUrl
                                 clientId:(NSString *)theClientId
                                secretKey:(NSString *)theSecretKey
                              redirectURI:(NSString *)theRedirectURI
                               withScopes:(NSArray *)theScopes; {
  
  NSParameterAssert(theBaseUrl);
  NSParameterAssert(theClientId);
  NSParameterAssert(theSecretKey);
  NSParameterAssert(theRedirectURI);
  SIOAuth2Client * client = [[self alloc] init];
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
  
  client.session = [NSURLSession SI_fetchSessionWithName:client.baseURLString] ? :
  [NSURLSession SI_buildSessionWithName:client.baseURLString
                      withBaseURLString:client.baseURLString
                andSessionConfiguration:sessionConfiguration
                   andRequestSerializer:[SIURLSessionRequestSerializerFormURLEncoding serializerWithOptions:nil]
                  andResponseSerializer:nil operationQueue:nil];

  [[SIOAuth2ClientManager sharedManager].clientMap setObject:client forKey:client.baseURLString];
  
  return client;
}


-(void)setAccessCredential:(SIOAccessCredential *)accessCredential; {
  _accessCredential = accessCredential;
  if(accessCredential) [self.session SI_setValue:[NSString stringWithFormat:@"Bearer %@", accessCredential.accessToken] forHTTPHeaderField:@"Authorization"];
  else [self.session SI_setValue:nil forHTTPHeaderField:@"Authorization"];
    


  
}

-(void)authenticateWithAuthorizationPath:(NSString *)theAuthorizationPath andTokenPath:(NSString *)theTokenPath
                              onComplete:(SIOAuth2ClientAuthenticationCompleteBlock)theBlock; {
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
  
  NSURL * requestUrl =[self.session SI_taskGETResource:theAuthorizationPath withParams:params.copy completeBlock:nil].currentRequest.URL;
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
  
  
  NSMutableDictionary * params = @{}.mutableCopy;
  [[theUrl.query componentsSeparatedByString:@"&"] enumerateObjectsUsingBlock:^(NSString * param, __unused NSUInteger idx, __unused  BOOL *stop) {
    NSArray * parts = [param componentsSeparatedByString:@"="];
    if(parts.count < 2) return;
    [params setObject:[parts objectAtIndex:1] forKey:[parts objectAtIndex:0]];
  }];
  
  
  if ([params[@"state"] isEqualToString:[self.session.SI_serializerForRequest escapedQueryValueFromString:self.nonceState]] == NO) {
    NSDictionary * userInfo = @{
                                NSLocalizedDescriptionKey:
                                  NSLocalizedStringFromTable(@"state_error", @"SIURLSessionBlocks", nil),

                                NSLocalizedFailureReasonErrorKey:
                                  NSLocalizedStringFromTable(@"The state code does not validate against CRSF protection", @"SIURLSessionBlocks", nil),
                                
                                NSURLErrorFailingURLErrorKey:theUrl
                                };
    
    NSError * error = [[NSError alloc] initWithDomain:NSURLErrorDomain code:NSURLErrorUserCancelledAuthentication userInfo:userInfo];
    self.authenticationCompletionBlock(nil, error);
   }
  
  else if(params[@"error"]) {
    NSDictionary * userInfo = @{
                                NSLocalizedDescriptionKey:
                                  [NSString stringWithFormat:NSLocalizedStringFromTable(@"%@", @"SIURLSessionBlocks", nil), params[@"error"]],
                                NSLocalizedFailureReasonErrorKey:
                                  [NSString stringWithFormat:NSLocalizedStringFromTable(@"%@", @"SIURLSessionBlocks", nil), params[@"error_description"]],
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
    [[self.session SI_taskPOSTResource:self.tokenPath withParams:postData completeBlock:^(NSError *error, NSDictionary *responseObject, NSHTTPURLResponse *urlResponse, NSURLSessionTask *task) {
      weakSelf.accessCredential = [SIOAccessCredential accessCredentialWithDictionary:responseObject];
      weakSelf.authenticationCompletionBlock(weakSelf.accessCredential, error);
    }] resume];
    
  }
  

  return YES;
}


-(void)refreshWithTokenPath:(NSString *)theTokenPath
                 onComplete:(SIOAuth2ClientAuthenticationCompleteBlock)theBlock; {
  NSParameterAssert(self.accessCredential);

  NSParameterAssert(self.session);

  NSDictionary * postData = @{@"grant_type" : @"refresh_token",
                              @"refresh_token" : self.accessCredential.refreshToken,
                              @"client_secret" : self.secretKey,
                              @"client_id" : self.clientId
                              };
  
  
  __weak typeof(self) weakSelf = self;
  [[self.session SI_taskPOSTResource:self.tokenPath withParams:postData completeBlock:^(NSError *error, NSDictionary *responseObject, NSHTTPURLResponse *urlResponse, NSURLSessionTask *task) {
    weakSelf.accessCredential = [SIOAccessCredential accessCredentialWithDictionary:responseObject];
    theBlock(weakSelf.accessCredential, error);
  }] resume];

  
}

-(void)requestWithResourcePath:(NSString *)theResourcePath
                    parameters:(NSDictionary *)theParameters
                    HTTPMethod:(NSString *)theHTTPMethod
                    onComplete:(SIOAuth2ClientRequestCompleteBlock)theBlock; {
  
  NSParameterAssert(theHTTPMethod);
  NSParameterAssert(theResourcePath);
  NSParameterAssert(self.session);
  
  [[self.session SI_buildTaskWithHTTPMethodString:theHTTPMethod onResource:theResourcePath params:theParameters completeBlock:^(NSError *error, NSDictionary *responseObject, NSHTTPURLResponse *urlResponse, NSURLSessionTask *task) {
        if(theBlock) theBlock(responseObject, error);
  }] resume];
  
  
}




@end

