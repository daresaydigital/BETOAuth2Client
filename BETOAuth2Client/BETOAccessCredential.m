
#import "BETOAccessCredential.h"
@interface BETOAccessCredential ()
@property(nonatomic,copy) NSString *accessToken;
@property(nonatomic,copy) NSString *tokenType;
@property(nonatomic,copy) NSString *refreshToken;
@property(nonatomic,copy) NSDate   * expiresAtDate;
+(instancetype)accessCredentialWithDictionary:(NSDictionary *)theDictionary;
@end


@implementation BETOAccessCredential

+(instancetype)accessCredentialWithDictionary:(NSDictionary *)theDictionary; {
  BETOAccessCredential * credential = [[[self class] alloc] init];
  credential.accessToken = theDictionary[@"access_token"];
  NSNumber * number = theDictionary[@"expires_in"];
  credential.expiresAtDate = [NSDate dateWithTimeIntervalSinceNow:number.integerValue];
  credential.tokenType = theDictionary[@"token_type"];
  credential.refreshToken = theDictionary[@"refresh_token"];
  if(credential.accessToken)
    return credential;
  else
    return nil;

}

-(NSTimeInterval)expiresInTimeInterval; {
  return [self.expiresAtDate timeIntervalSinceNow];
}

-(BOOL)isAboutToExpire; {
  return self.expiresInTimeInterval < 1000;
}


-(BOOL)isExpired; {
  return self.expiresInTimeInterval < 10.f;
}

-(instancetype)copyWithZone:(NSZone *)zone; {
  BETOAccessCredential * credential = [[super class] allocWithZone:zone];
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
  [aCoder encodeObject:self.expiresAtDate forKey:@"expiresAtDate"];
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
  return [NSString
          stringWithFormat:@"accessToken: %@ \n tokenType: %@ \n refreshToken: %@ \n expiresInDate: %@ \n expiresInTimeInterval: %f \n isExpired: %@ \n isAboutToExpire: %@ \n",
          self.accessToken,
          self.tokenType,
          self.refreshToken,
          self.expiresAtDate,
          self.expiresInTimeInterval,
          self.isExpired ? @"YES" : @"NO",
          self.isAboutToExpire ? @"YES" : @"NO"
          ];
}
@end