
@interface SIOAccessCredential : NSObject
<NSSecureCoding,NSCopying>
@property(nonatomic,copy,readonly) NSString * tokenType;
@property(nonatomic,copy,readonly) NSString * accessToken;
@property(nonatomic,copy,readonly) NSString * refreshToken;
@property(nonatomic,copy,readonly) NSDate   * expiresInDate;
@property(nonatomic,readonly) BOOL isExpired;
@property(nonatomic,readonly) BOOL isValid;
@end