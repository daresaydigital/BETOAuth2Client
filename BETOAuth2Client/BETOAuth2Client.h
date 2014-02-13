

#import "BETOAccessCredential.h"


typedef void (^BETOAuth2ClientAuthenticationCompletionBlock)(BETOAccessCredential * credential, NSError * error);
typedef void (^BETOAuth2ClientRequestCompletionBlock)(NSDictionary * responseObject, NSError * error, NSHTTPURLResponse * URLResponse);

typedef NS_ENUM(NSInteger, BETRequestEncodingType) {
  BETRequestEncodingTypeFormURLEncoding,
  BETRequestEncodingTypeJSON
};


@interface BETOAuth2Client : NSObject
#pragma mark Properties
@property(nonatomic,copy,readonly) NSString * identifier;
@property(nonatomic,copy,readonly) NSArray * scopes;
@property(nonatomic,copy,readonly) NSString * redirectURI;
@property(nonatomic,strong) BETOAccessCredential * accessCredential;
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
                              requestType:(BETRequestEncodingType)requestType;

#pragma mark - Authentication
-(void)authenticateWithResourceOwner:(NSString *)theUsername andPassword:(NSString *)thePassword
                            tokenPath:(NSString *)theTokenPath
                          completion:(BETOAuth2ClientAuthenticationCompletionBlock)theCompletion;

-(void)authenticateWithAuthorizationPath:(NSString *)theAuthorizationPath
                            tokenPath:(NSString *)theTokenPath
                              completion:(BETOAuth2ClientAuthenticationCompletionBlock)theCompletion;

#pragma mark - Delegation
-(BOOL)handleApplicationOpenURL:(NSURL *)theUrl
                onlyMatchingUrlPrefix:(NSString *)thePrefix
    withSourceApplicationString:(NSString *)theSourceApplicationString;

#pragma mark - Session
-(void)refreshWithTokenPath:(NSString *)theTokenPath
                   completion:(BETOAuth2ClientAuthenticationCompletionBlock)theCompletion;

#pragma mark - Requests
-(void)requestWithResourcePath:(NSString *)theResourcePath
                    parameters:(NSDictionary *)theParameters
                    HTTPMethod:(NSString *)theHTTPMethod
                    completion:(BETOAuth2ClientRequestCompletionBlock)theCompletion;

@end