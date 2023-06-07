//
//  RNSensitiveInfo.swift
//  RNSensitiveInfo
//
//  Created by Mayowa Olunuga on 02/06/2023.
//  Copyright © 2023 devfd. All rights reserved.
//

import Foundation
import LocalAuthentication
import Security
import UIKit

@objc(RNSensitiveInfo)
class RNSensitiveInfo: NSObject {
    
    @objc static func requiresMainQueueSetup() -> Bool { return true }
    
    @available(iOS 11.3, *)
    @objc(setItem:value:options:resolver:rejecter:)
    func setItem(
        _ key: String,
        value: String,
        options: [AnyHashable: Any],
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock)
    {
        var keychainService = options["keychainService"] as? String ?? "app"
        var sync = options["kSecAttrSynchronizable"] as? NSNumber ?? kSecAttrSynchronizableAny
        
        let valueData = value.data(using: .utf8)!
        var search: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: keychainService,
            kSecAttrSynchronizable: sync,
            kSecAttrAccount: key
        ]
        var query = search
        query[kSecValueData] = valueData
        if let touchID = options["touchID"] as? Bool, touchID {
            let kSecAccessControlValue = convertkSecAccessControl(key: options["kSecAccessControl"] as? String ?? "")
            let sac = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, kSecAccessControlValue, nil)
            query[kSecAttrAccessControl] = sac
        } else {
            let kSecAttrAccessibleValue = convertkSecAttrAccessible(key: options["kSecAttrAccessible"] as? String)
            query[kSecAttrAccessible] = kSecAttrAccessibleValue
        }
        
        var osStatus: OSStatus = SecItemAdd(query as CFDictionary, nil)
        if osStatus == errSecSuccess {
            resolve(value)
            return
        }
        if osStatus == errSecDuplicateItem {
            let update: [CFString: Any] = [kSecValueData: valueData]
            osStatus = SecItemUpdate(search as CFDictionary, update as CFDictionary)
        }
        if osStatus != noErr {
            let error = NSError(domain: NSOSStatusErrorDomain, code: Int(osStatus))
            reject(String(error.code), message(for: error), error)
            return
        }
        resolve(value)
    }
    
    @available(iOS 9.0, *)
    @objc func getItem(key: String, options: NSDictionary, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        var keychainService = options["keychainService"] as? String ?? "app"
        
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: key,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
            kSecReturnAttributes as String: kCFBooleanTrue as Any,
            kSecReturnData as String: kCFBooleanTrue as Any
        ]
        
        if let kSecUseOperationPrompt = options["kSecUseOperationPrompt"] as? String {
            query[kSecUseOperationPrompt as String] = kSecUseOperationPrompt
        }
        
        if let touchID = options["touchID"] as? Bool, touchID {
            let context = LAContext()
            let kLocalizedFallbackTitle = options["kLocalizedFallbackTitle"] as? String ?? ""
            context.localizedFallbackTitle = kLocalizedFallbackTitle
            context.touchIDAuthenticationAllowableReuseDuration = 1
            
            query[kSecUseAuthenticationContext as String] = context
            
            var prompt = ""
            if let kSecUseOperationPrompt = options["kSecUseOperationPrompt"] as? String {
                prompt = kSecUseOperationPrompt
            }
            
            let policy = kLocalizedFallbackTitle.isEmpty ? LAPolicy.deviceOwnerAuthentication : LAPolicy.deviceOwnerAuthenticationWithBiometrics
            
            context.evaluatePolicy(policy, localizedReason: prompt) { success, error in
                if !success {
                    if let error = error {
                        reject("\(error.code)", error.localizedDescription, error)
                    } else {
                        reject(nil, "The user name or passphrase you entered is not correct.", nil)
                    }
                    return
                }
                
                self.getItem(query: query, resolver: resolve, rejecter: reject)
            }
            return
        } else if let kSecAttrAccessible = options["kSecAttrAccessible"] as? String {
              let kSecAttrAccessibleValue = convertkSecAttrAccessible(key: kSecAttrAccessible)
                query[kSecAttrAccessible as String] = kSecAttrAccessibleValue
        }
        
        self.getItem(query: query, resolver: resolve, rejecter: reject)
    }
    
    @objc
    func hasItem(key: String, options: NSDictionary, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        var keychainService = options["keychainService"] as? String ?? "app"
        
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: key,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
            kSecReturnAttributes as String: kCFBooleanTrue as Any,
            kSecReturnData as String: kCFBooleanTrue as Any
        ]
        
        DispatchQueue.main.async {
            if UIApplication.shared.isProtectedDataAvailable {
                var found: NSDictionary?
                var foundTypeRef: CFTypeRef?
                let osStatus = SecItemCopyMatching(query as CFDictionary, &foundTypeRef)
                
                if osStatus != noErr && osStatus != errSecItemNotFound {
                    let error = NSError(domain: NSOSStatusErrorDomain, code: Int(osStatus), userInfo: nil)
                    reject(String(error.code), self.message(for: error), error)
                    return
                }
                
                found = foundTypeRef as? NSDictionary
                if found == nil {
                    resolve(false)
                } else {
                    resolve(true)
                }
            } else {
                reject("protected_data_unavailable", "Protected data not available yet. Retry operation", nil)
            }
        }
    }

    func getItem(with query: NSDictionary, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        var found: NSDictionary?
        var foundTypeRef: CFTypeRef?
        let osStatus = SecItemCopyMatching(query as CFDictionary, &foundTypeRef)
        
        if osStatus != noErr && osStatus != errSecItemNotFound {
            let error = NSError(domain: NSOSStatusErrorDomain, code: Int(osStatus), userInfo: nil)
            reject(String(error.code), message(for: error), error)
            return
        }
        
        found = foundTypeRef as? NSDictionary
        if found == nil {
            resolve("")
        } else {
            // Found
            let valueData = found![kSecValueData as NSString] as! Data
            let value = String(data: valueData, encoding: .utf8)
            resolve(value)
        }
    }
    
    @objc func getAllItems(options: NSDictionary, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        let keychainService = RCTConvert.nsString(options["keychainService"])
        
        var finalResult = [[String: Any]]()
        var query = [
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
            kSecReturnAttributes as String: kCFBooleanTrue ?? false,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnData as String: kCFBooleanTrue ?? false
        ] as [String: Any]
        
        if let keychainService = keychainService {
            query[kSecAttrService as String] = keychainService
        }
        
        let secItemClasses: [Any] = [
            kSecClassGenericPassword,
            kSecClassInternetPassword,
            kSecClassCertificate,
            kSecClassKey,
            kSecClassIdentity
        ]
        
        for secItemClass in secItemClasses {
            query[kSecClass as String] = secItemClass

            var result: AnyObject?
            let osStatus = SecItemCopyMatching(query as CFDictionary, &result)
            
            if osStatus == noErr {
                if let items = result as? [[String: Any]] {
                    for item in items {
                        var finalItem = [String: Any]()
                        if let service = item[kSecAttrService as String] as? String {
                            finalItem["service"] = service
                        }
                        if let key = item[kSecAttrAccount as String] as? String {
                            finalItem["key"] = key
                        }
                        if let valueData = item[kSecValueData as String] as? Data,
                           let value = String(data: valueData, encoding: .utf8) {
                            finalItem["value"] = value
                        }
                        
                        finalResult.append(finalItem)
                    }
                }
            }
        }
        
        if !finalResult.isEmpty {
            resolve([finalResult])
        } else {
            reject("no_events", "There were no events", [NSNull()])
        }
    }
    
    @objc func deleteItem(key: String, options: NSDictionary, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        var keychainService = RCTConvert.nsString(options["keychainService"])
        if keychainService == nil {
            keychainService = "app"
        }
        
        var sync = options["kSecAttrSynchronizable"]
        if sync == nil {
            sync = kSecAttrSynchronizableAny
        }

        // Create dictionary of search parameters
        let query: NSDictionary = [
            kSecClass as String: kSecClassGenericPassword as String,
            kSecAttrSynchronizable as String: sync!,
            kSecAttrService as String: keychainService!,
            kSecAttrAccount as String: key,
            kSecReturnAttributes as String: kCFBooleanTrue!,
            kSecReturnData as String: kCFBooleanTrue!
        ]

        // Remove any old values from the keychain
        let osStatus = SecItemDelete(query)
        if osStatus != noErr && osStatus != errSecItemNotFound {
            let error = NSError(domain: NSOSStatusErrorDomain, code: Int(osStatus), userInfo: nil)
            reject("\(error.code)", message(for: error), error)
            return
        }
        resolve("")
    }
    
    @available(iOS 11.0, *)
    @objc func isSensorAvailable(resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        #if !TARGET_OS_TV
        let context = LAContext()
        
        var evaluationError: NSError?
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &evaluationError) {
                if context.biometryType == .faceID {
                    resolve("Face ID")
                    return
                }
            resolve("Touch ID")
        } else {
            if let error = evaluationError, error.code == LAError.biometryLockout.rawValue {
                reject(String(error.code), "Biometry is locked", error)
                return
            }
            resolve(false)
        }
        #else
        resolve(false)
        #endif
    }

    func convertkSecAttrAccessible(key:String!) -> CFString{
        if key.isEqual("kSecAttrAccessibleAfterFirstUnlock") {
            return kSecAttrAccessibleAfterFirstUnlock
        }
        if key.isEqual("kSecAttrAccessibleAlways") {
            return kSecAttrAccessibleAlways
        }
        if key.isEqual("kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly") {
            return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        }
        if key.isEqual("kSecAttrAccessibleWhenUnlockedThisDeviceOnly") {
            return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
        if key.isEqual("kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly") {
            return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        }
        if key.isEqual("kSecAttrAccessibleAlwaysThisDeviceOnly") {
            return kSecAttrAccessibleAlwaysThisDeviceOnly
        }
        return kSecAttrAccessibleWhenUnlocked
    }

    @available(iOS 11.3, *)
    @objc
    func convertkSecAccessControl(key: String) -> SecAccessControlCreateFlags {
        if key.isEqual("kSecAccessControlApplicationPassword") {
            return .applicationPassword
        }
        if key.isEqual("kSecAccessControlPrivateKeyUsage") {
            return .privateKeyUsage
        }
        if key.isEqual("kSecAccessControlDevicePasscode") {
            return .devicePasscode
        }
        if key.isEqual("kSecAccessControlTouchIDAny") {
            return .biometryAny
        }
        if key.isEqual("kSecAccessControlTouchIDCurrentSet") {
            return .biometryCurrentSet
        }
        if key.isEqual("kSecAccessControlBiometryAny") {
            return .biometryAny
        }
        if key.isEqual("kSecAccessControlBiometryCurrentSet") {
            return .biometryCurrentSet
        }
        return .userPresence
    }
    
    func message(for error: NSError) -> String {
        switch error.code {
        case Int(errSecUnimplemented):
            return "Function or operation not implemented."
            
        case Int(errSecIO):
            return "I/O error."
            
        case Int(errSecOpWr):
            return "File already open with write permission."
            
        case Int(errSecParam):
            return "One or more parameters passed to a function were not valid."
            
        case Int(errSecAllocate):
            return "Failed to allocate memory."
            
        case Int(errSecUserCanceled):
            return "User canceled the operation."
            
        case Int(errSecBadReq):
            return "Bad parameter or invalid state for operation."
            
        case Int(errSecNotAvailable):
            return "No keychain is available. You may need to restart your computer."
            
        case Int(errSecDuplicateItem):
            return "The specified item already exists in the keychain."
            
        case Int(errSecItemNotFound):
            return "The specified item could not be found in the keychain."
            
        case Int(errSecInteractionNotAllowed):
            return "User interaction is not allowed."
            
        case Int(errSecDecode):
            return "Unable to decode the provided data."
            
        case Int(errSecAuthFailed):
            return "The username or passphrase you entered is not correct."
            
        default:
            return error.localizedDescription
        }
    }

}
