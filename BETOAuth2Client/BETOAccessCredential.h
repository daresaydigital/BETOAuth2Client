
@protocol BETOAccessing <NSSecureCoding,NSCopying>
@required
@property(nonatomic,copy,readonly) NSString * tokenType;
@property(nonatomic,copy,readonly) NSString * accessToken;
@property(nonatomic,copy,readonly) NSString * refreshToken;
@property(nonatomic,copy,readonly) NSDate   * expiresAtDate;
@property(nonatomic,readonly) NSTimeInterval expiresInTimeInterval;
@property(nonatomic,readonly) BOOL isExpired;
@property(nonatomic,readonly) BOOL isAboutToExpire;
@end

@interface BETOAccessCredential : NSObject
<BETOAccessing>
@end