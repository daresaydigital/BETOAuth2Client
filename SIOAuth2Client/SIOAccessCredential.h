
@protocol SIOAccessing <NSSecureCoding,NSCopying>
@required
@property(nonatomic,copy,readonly) NSString * tokenType;
@property(nonatomic,copy,readonly) NSString * accessToken;
@property(nonatomic,copy,readonly) NSString * refreshToken;
@property(nonatomic,copy,readonly) NSDate   * expiresAtDate;
@property(nonatomic,readonly) BOOL isExpired;

@end

@interface SIOAccessCredential : NSObject
<SIOAccessing>
@end