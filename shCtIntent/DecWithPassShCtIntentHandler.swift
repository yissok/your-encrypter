import Foundation
import Intents

class DecWithPassShCtIntentHandler: NSObject, DecWithPassShCtIntentHandling {
    
    
    func handle(intent: DecWithPassShCtIntent, completion: @escaping (DecWithPassShCtIntentResponse) -> Void) {
        if let inputText = intent.text {
            if let inputPass = intent.pass {
                completion(DecWithPassShCtIntentResponse.success(result: decLite(password: inputPass, input: inputText)))
            } else {
                completion(DecWithPassShCtIntentResponse.failure(error: "The entered text was invalid"))
            }
        } else {
            completion(DecWithPassShCtIntentResponse.failure(error: "The entered text was invalid"))
        }
    }
    
    func resolveText(for intent: DecWithPassShCtIntent, with completion: @escaping (DecWithPassShCtTextResolutionResult) -> Void) {
        if let text = intent.text, !text.isEmpty {
            completion(DecWithPassShCtTextResolutionResult.success(with: text))
        } else {
            completion(DecWithPassShCtTextResolutionResult.unsupported(forReason: .noText))
        }
    }
    
   func resolvePass(for intent: DecWithPassShCtIntent, with completion: @escaping (INStringResolutionResult) -> Void) {
       if let text = intent.pass, !text.isEmpty {
           completion(DecWithPassShCtTextResolutionResult.success(with: text))
       } else {
           completion(DecWithPassShCtTextResolutionResult.unsupported(forReason: .noText))
       }
   }

}

