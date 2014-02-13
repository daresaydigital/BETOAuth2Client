

#import "BETOAccessCredential.h"


typedef void (^BETOAuth2ClientAuthenticationCompleteBlock)(BETOAccessCredential * credential, NSError * error);
typedef void (^BETOAuth2ClientRequestCompleteBlock)(NSDictionary * responseObject, NSError * error, NSHTTPURLResponse * URLResponse);

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
@property(nonatomic,copy,readonly) BETOAuth2ClientAuthenticationCompleteBlock authenticationCompletionBlock;

#pragma mark - Shared
+(instancetype)existingOAuth2ClientWithIdentifier:(NSString *)theIdentifier;

#pragma mark - Initializer
+(instancetype)OAuth2ClientWithIdentifier:(NSString *)theIdentifier
                                  baseURL:(NSString *)theBaseUrl
                                 clientId:(NSString *)theClientId
                                secretKey:(NSString *)theSecretKey
                              redirectURI:(NSString *)theRedirectURI
                               withScopes:(NSArray *)theScopes
                              requestType:(BETRequestEncodingType)requestType;

#pragma mark - Authentication
-(void)authenticateWithResourceOwner:(NSString *)theUsername andPassword:(NSString *)thePassword
                            andTokenPath:(NSString *)theTokenPath
                              onComplete:(BETOAuth2ClientAuthenticationCompleteBlock)theBlock;

-(void)authenticateWithAuthorizationPath:(NSString *)theAuthorizationPath
                            andTokenPath:(NSString *)theTokenPath
                              onComplete:(BETOAuth2ClientAuthenticationCompleteBlock)theBlock;

#pragma mark - Delegation
-(BOOL)handleApplicationOpenURL:(NSURL *)theUrl
                onlyMatchingUrlPrefix:(NSString *)thePrefix
    withSourceApplicationString:(NSString *)theSourceApplicationString;

#pragma mark - Session
-(void)refreshWithTokenPath:(NSString *)theTokenPath
                 onComplete:(BETOAuth2ClientAuthenticationCompleteBlock)theBlock;

#pragma mark - Requests
-(void)requestWithResourcePath:(NSString *)theResourcePath
                    parameters:(NSDictionary *)theParameters
                    HTTPMethod:(NSString *)theHTTPMethod
                    onComplete:(BETOAuth2ClientRequestCompleteBlock)theBlock;

@end