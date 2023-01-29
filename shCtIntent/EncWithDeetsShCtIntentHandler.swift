import Foundation
import Intents


class EncWithDeetsShCtIntentHandler: NSObject, EncWithDeetsShCtIntentHandling {
    
    
    func handle(intent: EncWithDeetsShCtIntent, completion: @escaping (EncWithDeetsShCtIntentResponse) -> Void) {
        if let inputText = intent.text {
            if let inputPass = intent.pass {
                completion(EncWithDeetsShCtIntentResponse.success(result: encryptMessageWithDeets(input: inputText, password: inputPass)))
            } else {
                completion(EncWithDeetsShCtIntentResponse.failure(error: "The entered text was invalid"))
            }
        } else {
            completion(EncWithDeetsShCtIntentResponse.failure(error: "The entered text was invalid"))
        }
    }
    
    func resolveText(for intent: EncWithDeetsShCtIntent, with completion: @escaping (EncWithDeetsShCtTextResolutionResult) -> Void) {
        if let text = intent.text, !text.isEmpty {
            completion(EncWithDeetsShCtTextResolutionResult.success(with: text))
        } else {
            completion(EncWithDeetsShCtTextResolutionResult.unsupported(forReason: .noText))
        }
    }
    
   func resolvePass(for intent: EncWithDeetsShCtIntent, with completion: @escaping (INStringResolutionResult) -> Void) {
       if let text = intent.pass, !text.isEmpty {
           completion(EncWithDeetsShCtTextResolutionResult.success(with: text))
       } else {
           completion(EncWithDeetsShCtTextResolutionResult.unsupported(forReason: .noText))
       }
   }

}

