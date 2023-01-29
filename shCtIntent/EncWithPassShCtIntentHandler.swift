import Foundation
import Intents

class EncWithPassShCtIntentHandler: NSObject, EncWithPassShCtIntentHandling {
    
    
    func handle(intent: EncWithPassShCtIntent, completion: @escaping (EncWithPassShCtIntentResponse) -> Void) {
        if let inputText = intent.text {
            if let inputPass = intent.pass {
                completion(EncWithPassShCtIntentResponse.success(result: encLite(password: inputPass, input: inputText)))
            } else {
                completion(EncWithPassShCtIntentResponse.failure(error: "The entered text was invalid"))
            }
        } else {
            completion(EncWithPassShCtIntentResponse.failure(error: "The entered text was invalid"))
        }
    }
    
    func resolveText(for intent: EncWithPassShCtIntent, with completion: @escaping (EncWithPassShCtTextResolutionResult) -> Void) {
        if let text = intent.text, !text.isEmpty {
            completion(EncWithPassShCtTextResolutionResult.success(with: text))
        } else {
            completion(EncWithPassShCtTextResolutionResult.unsupported(forReason: .noText))
        }
    }
    
   func resolvePass(for intent: EncWithPassShCtIntent, with completion: @escaping (INStringResolutionResult) -> Void) {
       if let text = intent.pass, !text.isEmpty {
           completion(EncWithPassShCtTextResolutionResult.success(with: text))
       } else {
           completion(EncWithPassShCtTextResolutionResult.unsupported(forReason: .noText))
       }
   }

}

