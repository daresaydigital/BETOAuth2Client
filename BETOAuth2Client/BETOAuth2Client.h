

#import "BETOAuth2Credential.h"

typedef void (^BETOAuth2ClientAuthenticationCompletionBlock)(BETOAuth2Credential * credential, NSError * error);
typedef void (^BETOAuth2ClientRequestCompletionBlock)(id<NSFastEnumeration> responseObject, NSHTTPURLResponse * URLResponse, NSError * error);

typedef NS_ENUM(NSInteger, BETOAuth2ClientRequestEncodingType) {
  BETOAuth2ClientRequestEncodingTypeFormURLEncoding,
  BETOAuth2ClientRequestEncodingTypeJSON
};


@interface BETOAuth2Client : NSObject
#pragma mark Properties
@property(nonatomic,copy,readonly) NSString * identifier;
@property(nonatomic,copy,readonly) NSArray * scopes;
@property(nonatomic,copy,readonly) NSString * redirectURI;
@property(nonatomic,copy,readonly) NSString * webAuthURL; // is used to do the web authentication
@property(nonatomic,copy,readonly) NSString * theloaLevel;
@property(nonatomic,copy,readonly) NSString * theloginHint;
@property(nonatomic,copy,readonly) NSString * thePrompt;
@property(nonatomic,strong) BETOAuth2Credential * accessCredential;
@property(nonatomic,copy,readonly) BETOAuth2ClientAuthenticationCompletionBlock authenticationCompletion;

#pragma mark - Shared
+(instancetype)existingOAuth2ClientWithIdentifier:(NSString *)theIdentifier;

#pragma mark - Initializer
+(instancetype)OAuth2ClientWithIdentifier:(NSString *)theIdentifier
                                  baseURL:(NSString *)theBaseUrl
                                 clientId:(NSString *)theClientId
                                secretKey:(NSString *)theSecretKey
                              redirectURI:(NSString *)theRedirectURI
                               scopes:(NSArray *)theScopes
                              requestType:(BETOAuth2ClientRequestEncodingType)requestType;

-(void) setupAdditionalParamsWithloaLevel:(NSString *)theloaLevel
                                loginHint:(NSString *)theloginHint
                                   prompt:(NSString *)thePrompt;

-(void)setWebAuthURL:(NSString *)baseURLWeb;


#pragma mark - Authentication
-(void)authenticateWithResourceOwner:(NSString *)theUsername andPassword:(NSString *)thePassword
                            tokenPath:(NSString *)theTokenPath
                          completion:(BETOAuth2ClientAuthenticationCompletionBlock)theCompletion;
//web
-(void)authenticateWithAuthorizationPath:(NSString *)theAuthorizationPath
                            tokenPath:(NSString *)theTokenPath
                                  withUI:(Boolean)withUI
                              completion:(BETOAuth2ClientAuthenticationCompletionBlock)theCompletion;


#pragma mark - authorization code third party
-(void)authorizeThirdPartyCodeWithAuthorizationPath:(NSString *)theAuthorizationPath
                                         parameters:(id<NSFastEnumeration>)theParameters
                                             withUI:(Boolean)withUI
                                      completeBlock:(BETOAuth2ClientRequestCompletionBlock)theCompletion;
-(void)retrieveThirdPartyAccessCredentialWithTokenPath:(NSString *)theTokenPath
                                                 params:(NSDictionary *)params
                                             completion:(BETOAuth2ClientRequestCompletionBlock)theCompletion;

#pragma mark - Delegation
-(BOOL)handleApplicationOpenURL:(NSURL *)theUrl
                onlyMatchingUrlPrefix:(NSString *)thePrefix
    withSourceApplicationString:(NSString *)theSourceApplicationString;

#pragma mark - Session
-(void)refreshWithTokenPath:(NSString *)theTokenPath
                   completion:(BETOAuth2ClientAuthenticationCompletionBlock)theCompletion;

#pragma mark - Requests
-(void)requestWithResourcePath:(NSString *)theResourcePath
                    parameters:(id<NSFastEnumeration>)theParameters
                    HTTPMethod:(NSString *)theHTTPMethod
                    completion:(BETOAuth2ClientRequestCompletionBlock)theCompletion;

-(void)requestWithResourcePath:(NSString *)theResourcePath
                    parameters:(id<NSFastEnumeration>)theParameters
                    HTTPMethod:(NSString *)theHTTPMethod
                          data:(NSData *)data
                      mimeType:(NSString *)mimeType
                      filename:(NSString *)filename
                          name:(NSString *)name
                    completion:(BETOAuth2ClientRequestCompletionBlock)theCompletion;

#pragma mark - Client ID and secret as header
- (void)setAuthorizationHeaderFieldithClientID:(NSString *)clientID AndKey:(NSString *)clientSecret;


#pragma mark - Authentication policy engine

-(void)retrieveAuthenticationPolicyEngineListWithResourcePath:(NSString *)theResourcePath
                                                       params:(NSDictionary *)params
                                                   completion:(BETOAuth2ClientRequestCompletionBlock)theCompletion;

-(void)authenticateUserBySendingSMSWithPhoneNumber:(NSString *)thePhoneNumber
                                        completion:(BETOAuth2ClientRequestCompletionBlock)theCompletion;

-(void)authenticateUserUsingTwoFactorWithResourcePath:(NSString *)theResourcePath
                                               params:(NSDictionary *)params
                                           completion:(BETOAuth2ClientRequestCompletionBlock)theCompletion;
-(void)requestCurrentAuthenticationStatusOfTwoFactorWithResourcePath:(NSString *)theResourcePath
                                                        completion:(BETOAuth2ClientRequestCompletionBlock)theCompletion;



@end