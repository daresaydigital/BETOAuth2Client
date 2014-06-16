
#import "BETOAuth2Client.h"
#import <BETURLSession.h>
#import "BETURLSessionRequestSerializerFormURLEncoding.h"
#import "BETURLSessionRequestSerializerJSON.h"
#import "BETURLSessionResponseSerializerJSON.h"

static NSString * BETBase64EncodedStringFromString(NSString *string) {
    NSData *data = [NSData dataWithBytes:[string UTF8String] length:[string lengthOfBytesUsingEncoding:NSUTF8StringEncoding]];
    NSUInteger length = [data length];
    NSMutableData *mutableData = [NSMutableData dataWithLength:((length + 2) / 3) * 4];
    
    uint8_t *input = (uint8_t *)[data bytes];
    uint8_t *output = (uint8_t *)[mutableData mutableBytes];
    
    for (NSUInteger i = 0; i < length; i += 3) {
        NSUInteger value = 0;
        for (NSUInteger j = i; j < (i + 3); j++) {
            value <<= 8;
            if (j < length) {
                value |= (0xFF & input[j]);
            }
        }
        
        static uint8_t const kAFBase64EncodingTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        
        NSUInteger idx = (i / 3) * 4;
        output[idx + 0] = kAFBase64EncodingTable[(value >> 18) & 0x3F];
        output[idx + 1] = kAFBase64EncodingTable[(value >> 12) & 0x3F];
        output[idx + 2] = (i + 1) < length ? kAFBase64EncodingTable[(value >> 6)  & 0x3F] : '=';
        output[idx + 3] = (i + 2) < length ? kAFBase64EncodingTable[(value >> 0)  & 0x3F] : '=';
    }
    
    return [[NSString alloc] initWithData:mutableData encoding:NSASCIIStringEncoding];
}

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
@property(nonatomic,copy) BETOAuth2ClientAuthenticationCompletionBlock authenticationCompletionBlock;

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


-(void)setAccessCredential:(BETOAuth2Credential *)accessCredential; {
  _accessCredential = accessCredential;
  if(accessCredential) [self.session bet_setValue:[NSString stringWithFormat:@"Bearer %@", accessCredential.accessToken] forHTTPHeaderField:@"Authorization"];
  else [self.session bet_setValue:nil forHTTPHeaderField:@"Authorization"];
  
}


- (void)setAuthorizationHeaderFieldithClientIDAndKey;{
    NSString *basicAuthCredentials = [NSString stringWithFormat:@"%@:%@", self.clientId, self.secretKey];
    [self.session bet_setValue:[NSString stringWithFormat:@"Basic %@", BETBase64EncodedStringFromString(basicAuthCredentials)] forHTTPHeaderField:@"Authorization"];
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
                              completion:(BETOAuth2ClientAuthenticationCompletionBlock)theCompletion; {
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
  
  
  
  NSMutableDictionary * params = @{@"response_type" : @"code",
                                   @"client_id" : self.clientId,
                                   @"redirect_uri" : self.redirectURI,
                                   @"state" : self.nonceState
                                   }.mutableCopy;
  
  if(self.scopes && self.scopes.count > 0) [params addEntriesFromDictionary:@{@"scope" : [self.scopes componentsJoinedByString:@" "]}];
  
  NSURL * requestUrl =[self.session bet_taskGETResource:theAuthorizationPath withParams:params.copy completion:nil].currentRequest.URL;
  self.authenticationCompletionBlock = theCompletion;
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
    [[self.session bet_taskPOSTResource:self.tokenPath withParams:postData completion:^(BETResponse * response) {
     weakSelf.accessCredential = [BETOAuth2Credential accessCredentialWithDictionary:(NSDictionary *)response.content];
      weakSelf.authenticationCompletionBlock(weakSelf.accessCredential, response.error);
    }] resume];
    
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



@end

