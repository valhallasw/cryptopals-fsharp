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
    
    let decrypted = Aes.decryptCbcPkcs7 key iv encrypted |> Option.get
    printfn $"{decrypted |> Hex.byteToHex}"
    printfn $"{decrypted |> Ascii.byteToChars}"
    
    decrypted |> should equal input
    
[<Test>]
let challenge10 () =
    let input = File.readChallengeData "10.txt" |> String.concat "" |> Base64.base64ToByte
    let key = "YELLOW SUBMARINE" |> Ascii.charToByte
    let iv = Seq.replicate 16 0
    
    Aes.decryptCbcPkcs7 key iv input |> Option.get |> Seq.take 32 |> Ascii.byteToChars |> should equal "I'm back and I'm ringin' the bel"

let randomEncryption input =
    let key = Random.randomBytes 16
    let iv = Random.randomBytes 16
    
    let prepend_bytes = Random.randomBytes (Random.randomInt 5 10)
    let append_bytes = Random.randomBytes (Random.randomInt 5 10)
    
    let content = Seq.concat [prepend_bytes |> Seq.map int; input; append_bytes |> Seq.map int]
    
    if (Random.randomInt 0 2) = 1 then
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

let challenge12target: seq<int> -> seq<int> = challenge12target_template (Random.randomBytes 16)

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

let parsekv = String.split "&" >> Seq.map (String.split2 "=") >> Map

let profile_for email = $"email={email |> String.urlencode}&uid=10&role=user"

let challenge13key = Random.randomBytes 16 |> Seq.map int

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
    profile_for "foo@bar.com" |> should equal "email=foo%40bar.com&uid=10&role=user"
    
    encryptedprofile "foo@bar.com" |> getrole |> should equal "user"
    
    // email=foo%40bar. comm&uid=10&role =user\xe
    // email=whateve%40 admin&uid=10&rol e=user.......... etc
    //                  ^^^^^^^^^^^^^^^^
    // then build a new one with
    // email=foo%40bar. com&uid=10&role= user\xc\xc\xc\xc etc
    //                                   ^^^^^^^^^^^^^^^^ etc
    // and we can create
    // email=foo12@bar. com&uid=10&role= admin&uid=10&rol user\xc\xc\xc\xc
    //                                   ^^^^^^^^^^^^^^^^ ^^^^^^^^^^^^^^^^ (padding is still correct)
    
    let encrypted1 = "whateve@admin" |> encryptedprofile |> Seq.splitBlocks 16 |> Seq.toList
    let encrypted2 = "foo@bar.com" |> encryptedprofile |> Seq.splitBlocks 16 |> Seq.toList
    
    let modified = Seq.concat [ encrypted2[0]; encrypted2[1]; encrypted1[1]; encrypted2[2] ]
    
    getrole modified |> should equal "admin"


let challenge14target_template key prefix content =
    let secret_contents = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK" |> Base64.base64ToByte
    let to_encrypt = Seq.concat [prefix; content; secret_contents]
    //to_encrypt |> Hex.byteToHex |> printfn "%s"
    Aes.encryptEcbPkcs7 (key |> Seq.map int) to_encrypt

[<Test>]
let challenge14 () =
    let _key = Random.randomBytes 16
    let _prefix_length = Random.randomInt 10 100
    let _prefix = Random.randomBytes _prefix_length
    let challenge14target = challenge14target_template _key _prefix
    
    let mycontent = Seq.replicate (16*16) (int 'A')
    let encoded_firstattempt = challenge14target mycontent
    
    // we first need to figure out how much padding we need
    // to do so, we iteratively add 0, 1, ... 15 bytes until we find that we get something where
    // len(prefix) + len(pad) > 16 bytes, and thus the first *two* (or three, ....) blocks are
    // no longer recognisable
    // [RANDOMPREFIX][PAD]
    
    let first_block_mycontent = encoded_firstattempt |> Seq.chunkBySize 16 |> Seq.pairwise |> Seq.indexed |> Seq.filter (fun (i, (prev, next)) -> (prev = next)) |> Seq.head |> fst
    
    // we take the number of blocks here as guidance, and add random bytes until we find a padding where we hit a one-larger block
    // (although this fails if the prefix only takes an even number of bytes)
    
    let _secret_length_blocks_roundedup = int (ceil ((_prefix_length |> float) / 16.0)) 
    first_block_mycontent |> should equal _secret_length_blocks_roundedup
    
    printfn $"First attack block has index {first_block_mycontent}"
    
    // ok, so we know that the length of the random bytes block is (first_block_mycontent-2)*16 .. (first_block_mycontent-1)*16
    // either way, we should add padding until we find 16 repeated blocks that resemble the encrypted version of 'A'*16
    
    let AAAA_enc = encoded_firstattempt |> Seq.chunkBySize 16 |> Seq.item first_block_mycontent
    
    let test_blocks padding =
        let padding_bytes = Seq.replicate padding 1
        let encoded = challenge14target (Seq.append padding_bytes mycontent)
        let num_AAAA_blocks = encoded |> Seq.chunkBySize 16 |> Seq.filter ((=) AAAA_enc) |> Seq.length
        num_AAAA_blocks = 16
    
    let padding_length = seq { 1 .. 1 .. 16 } |> Seq.find test_blocks
    printfn $"Padding length is {padding_length}"
    
    padding_length |> should equal (16 - ((_prefix |> Seq.length) % 16))
    
    // we can now use the same method as challenge 12, but with everything shifted a few blocks.
    // For completeness, (re)calculate the prefix including the padding_length
    
    let padding_bytes = Seq.replicate padding_length 1
    let encoded_second = challenge14target (Seq.append padding_bytes mycontent)
    let prefix_and_padding_blocks = encoded_second |> Seq.chunkBySize 16 |> Seq.findIndex ((=) AAAA_enc)
    
    prefix_and_padding_blocks |> should equal (int ((_prefix_length |> float) / 16.0) + 1)
    
    // Now we make a "modified encryptor" that simply adds the correct padding and cuts off the prefix in the
    // output. We can then use the same cracking logic as challenge 12 (ecbCrackChar)
    let modified_encryptor content =
        Seq.append padding_bytes content |> challenge14target |> Seq.skip (prefix_and_padding_blocks * 16)
    
    let secret = Seq.unfold (ecbCrackChar modified_encryptor 16) Seq.empty

    printfn $"Decrypted secret:\n {secret |> Ascii.byteToChars}"
    printfn $"Single decrypted padding byte: 0x{secret |> Seq.last 1 |> Hex.byteToHex}"
    
[<Test>]
let challenge15 () =
    let unpad = Seq.map int >> Padding.strip_padding >> Option.map Ascii.byteToChars
    "ICE ICE BABY\x04\x04\x04\x04" |> unpad |> should equal (Some "ICE ICE BABY")
    "ICE ICE BABY\x05\x05\x05\x05" |> unpad |> should equal None
    "ICE ICE BABY\x05\x05\x05\x05" |> unpad |> should equal None
     
     
let challenge16enc_template key contents =
    let iv = Random.randomBytes 16
    let dec = ["comment1=cooking%20MCs;userdata="; contents |> String.urlencode; ";comment2=%20like%20a%20pound%20of%20bacon"] |> String.concat ""
    
    (iv, Aes.encryptCbcPkcs7 key iv (dec |> Ascii.charToByte)) 

let challenge16oracle_template key (iv, enc) =
    let decrypted = enc |> Aes.decryptCbcPkcs7 key iv
    
    decrypted |> Option.map Ascii.byteToChars |> Option.defaultValue "[padding invalid]" |> printfn "%s"
    
    decrypted |>
        Option.map (Ascii.byteToChars >> fun f -> f.Contains(";admin=true;")) |>
        Option.defaultValue false

[<Test>]
let challenge16 () =
    let _key = Random.randomBytes 16
    let enc = challenge16enc_template _key
    let oracle = challenge16oracle_template _key
    
    // add contents until we get a new block; in this case, we know the last block will be 16 \x10 bytes
    // we can then XOR this with the block we do want (including the padding to make it valid)
    
    let baselength = enc "" |> snd |> Seq.length
    let paddingAddsBytes x = Seq.replicate x "A" |> String.concat "" |> enc |> snd |> Seq.length |> ((<) baselength)
    
    let required_content_length = seq {1 .. 1 .. 16} |> Seq.find paddingAddsBytes
    
    let (iv, encdata) = Seq.replicate required_content_length "A" |> String.concat "" |> enc
    
    let newFinalBlock = ";admin=true;\x04\x04\x04\x04" |> Seq.map int
    let oldFinalBlock = Seq.replicate 16 16
    let xorBlock = Seq.pairxor oldFinalBlock newFinalBlock

    let encBlocks = encdata |> Seq.chunkBySize 16
    let mutatedBlockIndex = (encBlocks |> Seq.length) - 2
    
    let newEncData = Seq.concat [
        encBlocks |> Seq.take mutatedBlockIndex |> Seq.concat;
        encBlocks |> Seq.item mutatedBlockIndex |> Seq.pairxor xorBlock;
        encBlocks |> Seq.skip (mutatedBlockIndex + 1) |> Seq.concat
    ]
    
    (iv, newEncData) |> oracle |> should equal true

