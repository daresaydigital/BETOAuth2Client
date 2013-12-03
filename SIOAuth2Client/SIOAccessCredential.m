
#import "SIOAccessCredential.h"
@interface SIOAccessCredential ()
@property(nonatomic,copy) NSString *accessToken;
@property(nonatomic,copy) NSString *tokenType;
@property(nonatomic,copy) NSString *refreshToken;
@property(nonatomic,copy) NSDate   * expiresAtDate;
+(instancetype)accessCredentialWithDictionary:(NSDictionary *)theDictionary;
@end


@implementation SIOAccessCredential

+(instancetype)accessCredentialWithDictionary:(NSDictionary *)theDictionary; {
  SIOAccessCredential * credential = [[[self class] alloc] init];
  credential.accessToken = theDictionary[@"access_token"];
  NSNumber * number = theDictionary[@"expires_in"];
  credential.expiresAtDate = [NSDate dateWithTimeIntervalSinceNow:number.integerValue];
  credential.tokenType = theDictionary[@"token_type"];
  credential.refreshToken = theDictionary[@"refresh_token"];
  if(credential.refreshToken && credential.accessToken && credential.tokenType && credential.expiresAtDate)
    return credential;
  else
    return nil;

}

#warning Do not hardcode later.

-(BOOL)isExpired; {
  return NO;
}

-(instancetype)copyWithZone:(NSZone *)zone; {
  SIOAccessCredential * credential = [[super class] allocWithZone:zone];
  if(credential) {
    credential.accessToken   = self.accessToken;
    credential.tokenType     = self.tokenType;
    credential.refreshToken  = self.refreshToken;
    credential.expiresAtDate = self.expiresAtDate;
  }
  NSParameterAssert(credential);
  return credential;
}

-(void)encodeWithCoder:(NSCoder *)aCoder; {
  [aCoder encodeObject:self.accessToken forKey:@"accessToken"];
  [aCoder encodeObject:self.tokenType forKey:@"tokenType"];
  [aCoder encodeObject:self.refreshToken forKey:@"refreshToken"];
  [aCoder encodeObject:self.expiresAtDate forKey:@"expiresInDate"];
}

-(instancetype)initWithCoder:(NSCoder *)aDecoder; {
  self = [[[self class] alloc] init];
  if(self) {
    self.accessToken = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"accessToken"];
    self.tokenType = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"tokenType"];
    self.refreshToken = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"refreshToken"];
    self.expiresAtDate = [aDecoder decodeObjectOfClass:[NSDate class] forKey:@"expiresAtDate"];
  }
  NSParameterAssert(self);
  return self;
}

+(BOOL)supportsSecureCoding; {
  return YES;
}
-(NSString *)description; {
  return [NSString stringWithFormat:@"accessToken: %@ \n tokenType: %@ \n refreshToken: %@ \n expiresInDate: %@ \n isExpired: %@ \n",
          self.accessToken,
          self.tokenType,
          self.refreshToken,
          self.expiresAtDate,
          self.isExpired ? @"YES" : @"NO"
          ];
}
@end