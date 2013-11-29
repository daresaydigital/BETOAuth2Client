
#import "SIOAccessCredential.h"
@interface SIOAccessCredential ()
@property(nonatomic,copy) NSString *accessToken;
@property(nonatomic,copy) NSString *tokenType;
@property(nonatomic,copy) NSString *refreshToken;
@property(nonatomic,copy) NSDate   * expiresInDate;

@end


@implementation SIOAccessCredential

#warning Should probably not be hardcoded to NO

-(BOOL)isValid; {
  return !!(self.accessToken && self.tokenType && self.refreshToken && self.expiresInDate);
}

-(BOOL)isExpired; {
  return NO;
}

-(instancetype)copyWithZone:(NSZone *)zone; {
  SIOAccessCredential * credential = [[super class] allocWithZone:zone];
  if(credential) {
    credential.accessToken   = self.accessToken;
    credential.tokenType     = self.tokenType;
    credential.refreshToken  = self.refreshToken;
    credential.expiresInDate = self.expiresInDate;
  }
  NSParameterAssert(credential);
  return credential;
}

-(void)encodeWithCoder:(NSCoder *)aCoder; {
  [aCoder encodeObject:self.accessToken forKey:@"accessToken"];
  [aCoder encodeObject:self.tokenType forKey:@"tokenType"];
  [aCoder encodeObject:self.refreshToken forKey:@"refreshToken"];
  [aCoder encodeObject:self.expiresInDate forKey:@"expiresInDate"];
}

-(instancetype)initWithCoder:(NSCoder *)aDecoder; {
  self = [[[self class] alloc] init];
  if(self) {
    self.accessToken = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"accessToken"];
    self.tokenType = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"tokenType"];
    self.refreshToken = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"refreshToken"];
    self.expiresInDate = [aDecoder decodeObjectOfClass:[NSDate class] forKey:@"expiresInDate"];
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
          self.expiresInDate,
          self.isExpired ? @"YES" : @"NO"
          ];
}
@end