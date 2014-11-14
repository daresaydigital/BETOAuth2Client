
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


@interface BETOAuth2Credential ()

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
@property(nonatomic,copy) NSString * theloaLevel;
@property(nonatomic,copy) NSString * theloginHint;
@property(nonatomic,copy) NSString * thePrompt;
@property(nonatomic,copy) NSString * webAuthURL;
@property(nonatomic,copy) BETOAuth2ClientAuthenticationCompletionBlock authenticationCompletionBlock;
@property(nonatomic,copy) BETOAuth2ClientRequestCompletionBlock requestCompletionBlock;
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
                               scopes:(NSArray *)theScopes
                              requestType:(BETOAuth2ClientRequestEncodingType)requestType; {
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
    case BETOAuth2ClientRequestEncodingTypeJSON:
      request = [BETURLSessionRequestSerializerJSON new];
      break;
    case BETOAuth2ClientRequestEncodingTypeFormURLEncoding:
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

-(void)setWebAuthURL:(NSString *)baseURLWeb;{
    _webAuthURL = baseURLWeb;
}

-(void) setupAdditionalParamsWithloaLevel:(NSString *)theloaLevel
                                loginHint:(NSString *)theloginHint
                                   prompt:(NSString *)thePrompt;{
    self.theloaLevel = theloaLevel;
    self.theloginHint = theloginHint;
    self.thePrompt = thePrompt;
}


-(void)setAccessCredential:(BETOAuth2Credential *)accessCredential; {
  _accessCredential = accessCredential;
  if(accessCredential) [self.session bet_setValue:[NSString stringWithFormat:@"Bearer %@", accessCredential.accessToken] forHTTPHeaderField:@"Authorization"];
  else [self.session bet_setValue:nil forHTTPHeaderField:@"Authorization"];
  
}

- (void)setAuthorizationHeaderFieldithClientID:(NSString *)clientID AndKey:(NSString *)clientSecret;{
    NSString *basicAuthCredentials = [NSString stringWithFormat:@"%@:%@", clientID, clientSecret];
    [self.session bet_setValue:[NSString stringWithFormat:@"Basic %@", [[basicAuthCredentials dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:kNilOptions]] forHTTPHeaderField:@"Authorization"];
}

- (void)setAuthorizationHeaderFieldithClientIDAndKey;{
    NSString *basicAuthCredentials = [NSString stringWithFormat:@"%@:%@", self.clientId, self.secretKey];
    [self.session bet_setValue:[NSString stringWithFormat:@"Basic %@", [[basicAuthCredentials dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:kNilOptions]] forHTTPHeaderField:@"Authorization"];
}




-(void)authenticateWithResourceOwner:(NSString *)theUsername andPassword:(NSString *)thePassword
                        tokenPath:(NSString *)theTokenPath
                          completion:(BETOAuth2ClientAuthenticationCompletionBlock)theCompletion; {
  NSParameterAssert(theCompletion);
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
  self.authenticationCompletionBlock = theCompletion;
  NSURLSessionTask * task = [self.session bet_taskPOSTResource:theTokenPath withParams:params completion:^(BETResponse * response) {
    
    weakSelf.accessCredential = [BETOAuth2Credential accessCredentialWithDictionary:(NSDictionary *)response.content];
    weakSelf.authenticationCompletionBlock(weakSelf.accessCredential, response.error);
    
  }];
  
  
  [task resume];
  
  
  
  
  
}

-(void)authenticateWithAuthorizationPath:(NSString *)theAuthorizationPath
                            tokenPath:(NSString *)theTokenPath
                               withUI:(Boolean)withUI
                           completion:(BETOAuth2ClientAuthenticationCompletionBlock)theCompletion; {
    
     // NSParameterAssert(self.baseURLWeb);
      NSParameterAssert(theCompletion);
      NSParameterAssert(theAuthorizationPath);
      NSParameterAssert(theTokenPath);
      self.authorizationPath = theAuthorizationPath;
      self.tokenPath = theTokenPath;
      CFUUIDRef uuid = CFUUIDCreate(NULL);
      CFStringRef nonce = CFUUIDCreateString(NULL, uuid);
      CFRelease(uuid);
    
      self.nonceState = (NSString *)CFBridgingRelease(nonce);
      NSParameterAssert(self.nonceState);
    
      __weak typeof(self) weakSelf = self;
      NSMutableDictionary * params = @{@"response_type" : @"code",
                                       @"client_id" : self.clientId,
                                       @"redirect_uri" : self.redirectURI,
                                       @"state" : self.nonceState,
                                       @"nonce" : self.nonceState,
                                       @"acr_values":self.theloaLevel
                                       }.mutableCopy;
    
      if(self.scopes && self.scopes.count > 0) [params addEntriesFromDictionary:@{@"scope" : [self.scopes componentsJoinedByString:@" "]}];

    
    self.authenticationCompletionBlock = theCompletion;
    if(withUI){
//        NSURL * requestUrl =[self.session bet_taskGETResource:theAuthorizationPath withParams:params.copy completion:nil].currentRequest.URL;
//        self.authenticationCompletionBlock = theCompletion;
//        [[UIApplication sharedApplication] openURL:requestUrl];
        

        NSURL * redirectURL = [NSURL URLWithString:[self.webAuthURL stringByAppendingPathComponent:theAuthorizationPath]];
        NSString * queryparameter = nil;
        queryparameter = [[BETURLSessionSerializer new] queryStringFromParameters:params];
        redirectURL =  [NSURL URLWithString:[redirectURL.absoluteString
                                             stringByAppendingFormat:@"?%@",queryparameter]];

        [[UIApplication sharedApplication] openURL:redirectURL];

    }
    else{
        //TODO: should not show UI
        params[@"prompt"] = @"none";
        
        NSURL * redirectURL = [NSURL URLWithString:[self.webAuthURL stringByAppendingPathComponent:theAuthorizationPath]];
        NSString * queryparameter = nil;
        queryparameter = [[BETURLSessionSerializer new] queryStringFromParameters:params];
        redirectURL =  [NSURL URLWithString:[redirectURL.absoluteString
                                             stringByAppendingFormat:@"?%@",queryparameter]];

        
        NSURLSessionConfiguration *sessionconfig = [NSURLSessionConfiguration defaultSessionConfiguration];
        [sessionconfig setHTTPAdditionalHeaders:@{@"Accept": @"application/json"}];
        NSURLSession *session = [NSURLSession sessionWithConfiguration:sessionconfig];
       
        [[session dataTaskWithURL:redirectURL
                completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                    NSError *jsonError = nil;
                    id responseObject = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableContainers error:&jsonError];
                    __block __weak typeof(self) weakSelf = self;
                    if([responseObject isKindOfClass:[NSDictionary class]]){
                        NSMutableString *string  = [NSMutableString string];;
                       for (id key in responseObject) {
                            [string appendString:key];
                            [string appendString:@"="];
                            [string appendString:responseObject[key]];
                            [string appendString:@"&"];
                       }
                        NSString *newString = [string substringToIndex:[string length]-1];
                        NSString *urlString = [NSString stringWithFormat:@"%@?%@",weakSelf.redirectURI,newString];
                        NSURL *url = [NSURL URLWithString:[urlString stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding]];
                        [weakSelf handleApplicationOpenURL:url onlyMatchingUrlPrefix:weakSelf.redirectURI withSourceApplicationString:@"come.apple.mobilesafari"];
                        
                    }
                    else{
                       
                    }
                }] resume];
    }
    
}




-(void)authorizeThirdPartyCodeWithAuthorizationPath:(NSString *)theAuthorizationPath
                                         parameters:(id<NSFastEnumeration>)theParameters
                                             withUI:(Boolean)withUI
                                      completeBlock:(BETOAuth2ClientRequestCompletionBlock)theCompletion;{
    
    NSParameterAssert(theParameters);
    NSParameterAssert(theAuthorizationPath);
    
    
    NSString *httpMethod = withUI == YES ? @"POST":@"GET";
    [self requestWithResourcePath:theAuthorizationPath parameters:theParameters HTTPMethod:httpMethod completion:^(id<NSFastEnumeration> responseObject, NSHTTPURLResponse *URLResponse, NSError *error) {
         if(theCompletion) theCompletion(responseObject,URLResponse,error);
    }];
    
}



-(void)retrieveThirdPartyAccessCredentialWithTokenPath:(NSString *)theTokenPath
                                                  params:(NSDictionary *)params
                                            completion:(BETOAuth2ClientRequestCompletionBlock)theCompletion;{
    
    __weak typeof(self) weakSelf = self;
    NSLog(@"self.session %@",self.session.configuration.HTTPAdditionalHeaders);
 
    [[self.session bet_taskPOSTResource:theTokenPath withParams:params completion:^(BETResponse * response) {
        NSLog(@"weakself response %@",response);
        weakSelf.accessCredential = [BETOAuth2Credential accessCredentialWithDictionary:(NSDictionary *)response.content];
        if(theCompletion) theCompletion(response.content, response.HTTPURLResponse,response.error);
    }] resume];
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
      [self retrieveThirdPartyAccessCredentialWithTokenPath:self.tokenPath params:postData completion:^(id<NSFastEnumeration> responseObject, NSHTTPURLResponse *URLResponse, NSError *error) {
          weakSelf.accessCredential = [BETOAuth2Credential accessCredentialWithDictionary:responseObject];
          weakSelf.authenticationCompletionBlock(weakSelf.accessCredential, error);
      }];

}
  
  
  return YES;
}


-(void)refreshWithTokenPath:(NSString *)theTokenPath
                 completion:(BETOAuth2ClientAuthenticationCompletionBlock)theCompletion; {

  NSParameterAssert(self.accessCredential);
  NSParameterAssert(self.accessCredential.refreshToken);
  NSParameterAssert(self.secretKey);
  NSParameterAssert(self.clientId);
  NSParameterAssert(self.session);
  

    
     NSDictionary * postData = @{@"grant_type" : @"refresh_token",
                              @"refresh_token" : self.accessCredential.refreshToken
                              };

  __weak typeof(self) weakSelf = self;

  [self setAuthorizationHeaderFieldithClientIDAndKey];
  [[self.session bet_taskPOSTResource:theTokenPath withParams:postData completion:^(BETResponse * response) {
    weakSelf.accessCredential = [BETOAuth2Credential accessCredentialWithDictionary:(NSDictionary *)response.content];
    if(theCompletion) theCompletion(weakSelf.accessCredential, response.error);
  }] resume];
  
  
}

-(void)requestWithResourcePath:(NSString *)theResourcePath
                    parameters:(id<NSFastEnumeration>)theParameters
                    HTTPMethod:(NSString *)theHTTPMethod
                    completion:(BETOAuth2ClientRequestCompletionBlock)theCompletion; {
  
  NSParameterAssert(theHTTPMethod);
  NSParameterAssert(theResourcePath);
  NSParameterAssert(self.session);
  
  [[self.session bet_buildTaskWithHTTPMethodString:theHTTPMethod onResource:theResourcePath params:theParameters completion:^(BETResponse * response) {
    if(theCompletion) theCompletion(response.content, response.HTTPURLResponse, response.error);
  }] resume];
  
  
}


#pragma mark - Authentication policy engine

-(void)retrieveAuthenticationPolicyEngineListWithResourcePath:(NSString *)theResourcePath
                                                       params:(NSDictionary *)params
                                                   completion:(BETOAuth2ClientRequestCompletionBlock)theCompletion;{
    NSParameterAssert(theResourcePath);
    NSParameterAssert(params);
    NSParameterAssert(theCompletion);
    [[self.session bet_taskGETResource:theResourcePath withParams:params completion:^(BETResponse *response) {
        if(theCompletion) theCompletion(response.content, response.HTTPURLResponse, response.error);
    }] resume];
    
}

-(void)authenticateUserBySendingSMSWithPhoneNumber:(NSString *)thePhoneNumber
                                        completion:(BETOAuth2ClientRequestCompletionBlock)theCompletion;{
    
}


-(void)authenticateUserUsingTwoFactorWithResourcePath:(NSString *)theResourcePath
                                               params:(NSDictionary *)params
                                           completion:(BETOAuth2ClientRequestCompletionBlock)theCompletion;{
    NSParameterAssert(theResourcePath);
    NSParameterAssert(params);
    NSParameterAssert(theCompletion);
    [[self.session bet_taskPOSTResource:theResourcePath withParams:params completion:^(BETResponse *response) {
        if(theCompletion) theCompletion(response.content, response.HTTPURLResponse, response.error);
    }] resume];
}


-(void)requestCurrentAuthenticationStatusOfTwoFactorWithResourcePath:(NSString *)theResourcePath
                                                          completion:(BETOAuth2ClientRequestCompletionBlock)theCompletion;{
    NSParameterAssert(theCompletion);
    self.requestCompletionBlock = theCompletion;
    [[self.session bet_taskGETResource:theResourcePath withParams:nil completion:^(BETResponse *response) {
        if(theCompletion) theCompletion(response.content, response.HTTPURLResponse,response.error);
    }] resume];
}


@end

