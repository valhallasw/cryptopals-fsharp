module set4

open System
open System.Collections.Generic
open System.Security.Cryptography
open Microsoft.FSharp.Collections
open NUnit.Framework
open FsUnit
open cryptopals
open Utils


[<Test>]
let challenge25 () =
    let _key = Random.randomBytes 16
    let _nonce = Random.randomBytes 8
    let _content = File.readChallengeData "25.txt" |> String.concat "" |>
                  Base64.base64ToByte |>
                  Aes.decryptEcbPkcs7 ("YELLOW SUBMARINE" |> Ascii.charToByte)
    
    let ciphertext = _content |> Aes.encryptCtr _key _nonce
    
    let _changeContent key nonce enc index newtext =
        let keystream = Aes.genAesCtrStream key nonce
        Seq.concat [
            enc |> Seq.take index
            Seq.pairxor newtext (keystream |> Seq.skip index)
            enc |> Seq.skip index |> Seq.skip (Seq.length newtext)
        ]
    
    let changeContent = _changeContent _key _nonce
    
    // test whether this works...
    let c = "Hello, I like cookies" |> Ascii.charToByte |> Aes.encryptCtr _key _nonce
    let c1 = changeContent c 14 ("poc" |> Ascii.charToByte)
    
    c1 |> Aes.decryptCtr _key _nonce |> Ascii.byteToChars |> should equal "Hello, I like pockies"
    
    // great. Now we can recover the keystream from the ciphertext by replacing the content with
    // nul bytes
    let keystream = changeContent ciphertext 0 (Seq.replicate (Seq.length ciphertext) 0)
    
    // and thus we can decrypt the original ciphertext
    let content = Seq.pairxor ciphertext keystream
    content |> Seq.take 25 |> Ascii.byteToChars |> should equal "I'm back and I'm ringin' "
    
    