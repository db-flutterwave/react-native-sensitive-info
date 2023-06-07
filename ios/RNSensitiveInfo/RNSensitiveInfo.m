//
//  RNSensitiveInfoBridge.m
//  RNSensitiveInfo
//
//  Created by Mayowa Olunuga on 06/06/2023.
//  Copyright © 2023 devfd. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(RNSensitiveInfo, NSObject)

RCT_EXTERN_METHOD(setItem: (NSString*)key value:(NSString*)value options:(NSDictionary *)options resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject);

@end
