

#import "SIOAccessCredential.h"


typedef void (^SIOAuth2ClientAuthenticationCompleteBlock)(SIOAccessCredential * credential, NSError * error);
typedef void (^SIOAuth2ClientRequestCompleteBlock)(NSDictionary * responseObject, NSError * error);

typedef NS_ENUM(NSInteger, SIORequestEncodingType) {
  SIORequestEncodingTypeFormURLEncoding,
  SIORequestEncodingTypeJSON
};


@interface SIOAuth2Client : NSObject
#pragma mark Properties
@property(nonatomic,copy,readonly) NSArray * scopes;
@property(nonatomic,copy,readonly) NSString * redirectURI;
@property(nonatomic,strong) SIOAccessCredential * accessCredential;
@property(nonatomic,copy,readonly) SIOAuth2ClientAuthenticationCompleteBlock authenticationCompletionBlock;

#pragma mark - Initializer
+(instancetype)fetchOAuth2ClientWithURLBaseURL:(NSString *)theBaseUrl;


+(instancetype)OAuth2ClientWithURLBaseURL:(NSString *)theBaseUrl
                                 clientId:(NSString *)theClientId
                                secretKey:(NSString *)theSecretKey
                              redirectURI:(NSString *)theRedirectURI
                               withScopes:(NSArray *)theScopes
                              requestType:(SIORequestEncodingType)requestType;

-(void)authenticateWithResourceOwner:(NSString *)theUsername andPassword:(NSString *)thePassword
                            andTokenPath:(NSString *)theTokenPath
                              onComplete:(SIOAuth2ClientAuthenticationCompleteBlock)theBlock;

-(void)authenticateWithAuthorizationPath:(NSString *)theAuthorizationPath
                            andTokenPath:(NSString *)theTokenPath
                              onComplete:(SIOAuth2ClientAuthenticationCompleteBlock)theBlock;


-(BOOL)handleApplicationOpenURL:(NSURL *)theUrl
                onlyMatchingUrlPrefix:(NSString *)thePrefix
    withSourceApplicationString:(NSString *)theSourceApplicationString;

-(void)refreshWithTokenPath:(NSString *)theTokenPath
                 onComplete:(SIOAuth2ClientAuthenticationCompleteBlock)theBlock;

-(void)requestWithResourcePath:(NSString *)theResourcePath
                    parameters:(NSDictionary *)theParameters
                    HTTPMethod:(NSString *)theHTTPMethod
                    onComplete:(SIOAuth2ClientRequestCompleteBlock)theBlock;

@end