module set2

open System
open System.Collections.Generic
open Microsoft.FSharp.Collections
open NUnit.Framework
open FsUnit
open cryptopals


[<Test>]
let challenge1 () =
    "YELLOW SUBMARINE" |> Ascii.charToByte |> Padding.pad_pkcs7 20 |> Seq.map char |> should equal "YELLOW SUBMARINE\x04\x04\x04\x04"
    "YELLOW SUBMARINE" |> Ascii.charToByte |> Padding.pad_pkcs7 16 |> Seq.map char |> should equal "YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"

[<Test>]
let testDecryptEncryptBlock () =
    let enc = File.readChallengeData "7.txt" |> String.concat "" |> Base64.base64ToByte
    let key = "YELLOW SUBMARINE" |> Ascii.charToByte
    
    let block = enc |> Seq.take 16
    
    block |> Aes.decryptBlock key |> Ascii.byteToChars |> should equal "I'm back and I'm"
    "I'm back and I'm" |> Ascii.charToByte |> Aes.encryptBlock key |> should equal block

    (fun() -> enc |> Seq.take 15 |> Aes.decryptBlock key |> ignore) |> should throw typeof<System.ArgumentException>
    
[<Test>]
let testEncryptDecryptCBC () =
    let input = "I'm back and I'm ringin' the bell. Lorem ipsum dolor sit amet, consectetur adipiscing elit." |> Ascii.charToByte
    let key = "YELLOW SUBMARINE" |> Ascii.charToByte
    let iv = Seq.replicate 16 0
    
    let comparison = File.readChallengeData "7.txt" |> String.concat "" |> Base64.base64ToByte |> Seq.take 32 |> Hex.byteToHex
    printfn $"{comparison}"
    
    let encrypted = Aes.encryptCbcPkcs7 key iv input
    printfn $"{encrypted |> Hex.byteToHex}"
    
    let decrypted = Aes.decryptCbcPkcs7 key iv encrypted
    printfn $"{decrypted |> Hex.byteToHex}"
    printfn $"{decrypted |> Ascii.byteToChars}"
    
    decrypted |> should equal input
    
[<Test>]
let challenge10 () =
    let input = File.readChallengeData "10.txt" |> String.concat "" |> Base64.base64ToByte
    let key = "YELLOW SUBMARINE" |> Ascii.charToByte
    let iv = Seq.replicate 16 0
    
    Aes.decryptCbcPkcs7 key iv input |> Seq.take 32 |> Ascii.byteToChars |> should equal "I'm back and I'm ringin' the bel"

let randomInt min max = int (Random.Shared.NextInt64((int64) min, (int64) max))
let randomBytes size =
    let array = Array.create size (byte 0)
    Random.Shared.NextBytes array
    array |> Seq.map int

let randomEncryption input =
    let key = randomBytes 16
    let iv = randomBytes 16
    
    let prepend_bytes = randomBytes (randomInt 5 10)
    let append_bytes = randomBytes (randomInt 5 10)
    
    let content = Seq.concat [prepend_bytes |> Seq.map int; input; append_bytes |> Seq.map int]
    
    if (randomInt 0 2) = 1 then
        printf "CBC -> "
        Aes.encryptCbcPkcs7 key iv content
    else
        printf "ECB -> "
        Aes.encryptEcbPkcs7 key content

let oracle fn =
    let content = Seq.replicate 1024 0
    let encrypted = fn content
    
    // assume block size of 16, but this will also work with 32 etc.
    let duplicates = encrypted |> Seq.splitBlocks 16 |> Seq.map Seq.toArray |> Seq.countDuplicates
    if duplicates = 0 then "CBC" else "ECB"

[<Test>]
let challenge11 () =
    for i in {0 .. 1 .. 20} do
        oracle randomEncryption |> printfn "%s"

let challenge12target_template key content =
    let secret_contents = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK" |> Base64.base64ToByte

    Aes.encryptEcbPkcs7 (key |> Seq.map int) (Seq.append content secret_contents)

let challenge12target: seq<int> -> seq<int> = challenge12target_template (randomBytes 16)

let ecbCrackChar fn bs knownsecret =
    let A = 'A' |> Ascii.charToVal
    let S = 'S' |> Ascii.charToVal
    
    let prefix = Seq.replicate bs A
    let ks_withprefix = Seq.append prefix knownsecret
    
    let nextPos = ks_withprefix |> Seq.length
    let shift = bs - (nextPos % bs) - 1
    
    // construct attack: [test_1, unknown_char, shift, prefix] 
    let test_1 = ks_withprefix |> Seq.last (bs - 1)
    let shift_chars = Seq.replicate shift S
    
    let isMatch (char: int) =
        let content = [test_1; [char;]; shift_chars; prefix] |> Seq.concat
        //content |> Ascii.byteToChars |> printf "Test: %s ->"
        
        let blocks = content |> fn |> Seq.splitBlocks bs |> Seq.toList
        
        //blocks |> Seq.map Hex.byteToHex |> String.concat " " |> printfn "%s"
        
        let compareBlock = (nextPos / 16) + 1
        (Seq.toList blocks[0]) = (Seq.toList blocks[compareBlock])
    
    try
        let nextChar = {0 .. 1 .. 255} |> Seq.find isMatch
        Some (nextChar, Seq.append knownsecret [nextChar])
    with
        | :? KeyNotFoundException -> None  // at this point, we've hit the padding, which will not be consistent with our char-wise approach
        
let buildIteratively fn initial =
    Seq.append initial (Seq.unfold (fun state -> fn state |> Option.map (fun t -> (t, Seq.append state [t]))) initial)
    
[<Test>]
let testUnfold () =
    let buildUntilFiveLong state =
        if state < 5 then Some(state, state + 1) else None

    Seq.unfold buildUntilFiveLong 0 |> should equal [0; 1; 2; 3; 4]
    

[<Test>]
let challenge12 () =
    // determine block size through the first jump in length
    let encrypted_length shift = Seq.replicate shift 0 |> challenge12target |> Seq.length 
    let baselength = encrypted_length 0
    let length_increase shift = (encrypted_length shift) - baselength
    
    let blocksize = {1 .. 1 .. 64} |> Seq.map length_increase |> Seq.find (fun x -> x > 0)
    
    blocksize |> should equal 16

    // using blocksize, verify the encryption is using ECB
    let lotsOfAs = Seq.replicate 1024 ('A' |> Ascii.charToVal) |> challenge12target
    lotsOfAs |> Seq.splitBlocks blocksize |> Seq.map Seq.toList |> Seq.countDuplicates |> should be (greaterThan 0)

    // then crack step by step (see Challenge12.xlsx)
    let secret = Seq.unfold (ecbCrackChar challenge12target blocksize) Seq.empty
        
    printfn $"Decrypted secret:\n {secret |> Ascii.byteToChars}"
    printfn $"Single decrypted padding byte: 0x{secret |> Seq.tail |> Hex.byteToHex}"


module String =
    let split (key: string) (x: string) = x.Split(key) |> seq
    let split2 (key: string) (x: string): (string * string) =
        let result = x.Split(key, 2)
        match result with
            | [| a |] -> (a, "")
            | [| a; b |] -> (a, b)
            | _ -> failwith "todo"
            
    let replace (f: string) (t: string) (s: string) = s.Replace(f, t)
    

let parsekv = String.split "&" >> Seq.map (String.split2 "=") >> Map

let urlencode = String.replace "%" "%25" >> String.replace "&" "%26" >> String.replace "=" "%3D" 

let profile_for email = $"email={email |> urlencode}&uid=10&role=user"

let challenge13key = randomBytes 16 |> Seq.map int

let encryptedprofile email =
    email |> profile_for |> Ascii.charToByte |> Aes.encryptEcbPkcs7 challenge13key

let getrole enc =
    let dec = enc |> Aes.decryptEcbPkcs7 challenge13key
    let disp: string = dec |> Seq.map char |> String.Concat
    printfn $"{disp}"          
    dec |> (Ascii.byteToChars >> parsekv >> Map.find "role")

[<Test>]
let challenge13 () =
    "foo=bar&baz=qux&zap=zazzle" |> parsekv |> should equal (Map [("foo", "bar"); ("baz", "qux"); ("zap", "zazzle")])
    profile_for "foo@bar.com" |> should equal "email=foo@bar.com&uid=10&role=user"
    
    encryptedprofile "foo@bar.com" |> getrole |> should equal "user"
    
    // email=foo@bar.co m&uid=10&role=us er\xe
    // email=whatever@a admin&uid=10&rol e=user.......... etc
    //                  ^^^^^^^^^^^^^^^^
    // then build a new one with
    // email=foo12@bar. com&uid=10&role= user\xc\xc\xc\xc etc
    //                                   ^^^^^^^^^^^^^^^^ etc
    // and we can create
    // email=foo12@bar. com&uid=10&role= admin&uid=10&rol user\xc\xc\xc\xc
    //                                   ^^^^^^^^^^^^^^^^ ^^^^^^^^^^^^^^^^ (padding is still correct)
    
    let encrypted1 = "whatever@aadmin" |> encryptedprofile |> Seq.splitBlocks 16 |> Seq.toList
    let encrypted2 = "foo12@bar.com" |> encryptedprofile |> Seq.splitBlocks 16 |> Seq.toList
    
    let modified = Seq.concat [ encrypted2[0]; encrypted2[1]; encrypted1[1]; encrypted2[2] ]
    
    getrole modified |> should equal "admin"
    