module set3

open System
open System.Collections.Generic
open Microsoft.FSharp.Collections
open NUnit.Framework
open FsUnit
open cryptopals
open Utils

let xorPenultimateBlock content xorBlock =
    let encBlocks = content |> Seq.chunkBySize (xorBlock |> Seq.length)
    let mutatedBlockIndex = Seq.length encBlocks - 2

    Seq.concat [
        encBlocks |> Seq.take mutatedBlockIndex |> Seq.concat;
        encBlocks |> Seq.item mutatedBlockIndex |> Seq.pairxor xorBlock;
        encBlocks |> Seq.skip (mutatedBlockIndex + 1) |> Seq.concat
    ]

let decrypt_last_block oracle iv enc =
    let combined_enc = Seq.append iv enc
    let blockSize = iv |> Seq.length
    let zero_IV = Seq.replicate blockSize 0
        
    let decodesAsValid block =
        xorPenultimateBlock combined_enc block |> oracle zero_IV |> Option.isSome

    let buildBlocks (template: seq<int>) (index: int) (values: seq<int>) =
        values |> Seq.map (fun x -> (x, template |> Seq.withreplace index x))
    
    let allBytes = seq { 0 .. 1 .. 255 }

    // we attack from right to left; start with the final byte which needs special handling

    let possibleLastXorBytes = buildBlocks (Seq.replicate blockSize 0) (blockSize - 1) allBytes |> Seq.where (snd >> decodesAsValid) |> Seq.map fst
    let lastXorByte = possibleLastXorBytes |> buildBlocks (Seq.replicate blockSize 255) (blockSize - 1) |> Seq.where (snd >> decodesAsValid) |> Seq.map fst |> Seq.single |> Option.get
    
    let finalByte = 0x01 ^^^ lastXorByte
    
    // good, we can now attack the other bytes one by one. Assume we're going to Seq.fold this and we build this into a
    // state that contains the collected bytes
    let state = Seq.append (Seq.replicate (blockSize-1) 0) [ finalByte; ]
    
    let folder state index =
        let target_padding = (blockSize - index)
        let template = Seq.pairxor (Seq.replicate blockSize target_padding) state
        let xorByte = buildBlocks template index allBytes |> Seq.where (snd >> decodesAsValid) |> Seq.map fst |> Seq.single |> Option.get
        let actualByte = xorByte ^^^ target_padding
        
        state |> Seq.withreplace index actualByte

    seq { (blockSize - 2) .. -1 .. 0 } |> Seq.fold folder state  

let decrypt_all oracle iv enc =
    let blockSize = iv |> Seq.length
    let chunked = enc |> Seq.chunkBySize blockSize
    
    let process_chunk index =
        let to_attack = chunked |> Seq.take (index + 1) |> Seq.concat
        decrypt_last_block oracle iv to_attack

    seq { 0 .. 1 .. ((chunked |> Seq.length) - 1) } |> Seq.map process_chunk |> Seq.concat


[<Test>]
let challenge17_playground () =
    // first, let's play around a bit. Let's take a look at a block of content with one, two and three padding bytes
    let content_pad1 = "0123456789abcdef0123456789abcde" |> Ascii.charToByte
    let content_pad2 = "0123456789abcdef0123456789abcd" |> Ascii.charToByte
    let content_pad3 = "0123456789abcdef0123456789abc" |> Ascii.charToByte

    let key = Random.randomBytes 16
    let iv = Random.randomBytes 16
    
    // we can now attack the last byte. If the padding is correct, the last byte is PROBABLY 0x01 (see next step)
    // and we will find this by XORing the one-before-last block with all zeros.
    // however if the last byte is 0x02, we'd find a match for BOTH 0x00 (which leaves the last block to end with 0202)
    // AND 0x01 (which leaves the last block to end with 0201 -- also a valid padding, but with length 1)

    let getvalidXors enc =
        let fifteenZeros = Seq.replicate 15 0
        seq {0 .. 1 .. 255 } |>
             Seq.map (Seq.singleton >> Seq.append fifteenZeros >> xorPenultimateBlock enc >> Aes.decryptCbc key iv) |>
             Seq.indexed |>
             Seq.filter (snd >> Padding.strip_padding >> Option.isSome)

    // for a padding of length 1, only 0x00 is a valid xor
    Aes.encryptCbcPkcs7 key iv content_pad1 |> getvalidXors |> Seq.map fst |> should equal [0x00; ]
    
    // for a padding of length 2, we can either use 0x00 (leaving the last bytes to be 0202) or 0x03
    // to make the last bytes 0201 (as 0x03 ^ 0x02 = 0x01)
    Aes.encryptCbcPkcs7 key iv content_pad2 |> getvalidXors |> Seq.map fst |> should equal [0x00; 0x03]
    
    // for a padding of length 3, we can either use 0x03 (030303) or 0x02 (030301)
    Aes.encryptCbcPkcs7 key iv content_pad3 |> getvalidXors |> Seq.map fst |> should equal [0x00; 0x02]
    
    // in this case, we can mess with the previous byte to get the value that results in 030301. After all,
    // 03ff01 is valid, but 03ff03 is not!
    let pad3_enc = Aes.encryptCbcPkcs7 key iv content_pad3
    [0x00; 0x02] |> Seq.filter (
        Seq.singleton >>
        Seq.append [0;0;0;0;0;0;0;0;0;0;0;0;0;0;255] >>
        xorPenultimateBlock pad3_enc >>
        Aes.decryptCbc key iv >>
        Padding.strip_padding >>
        Option.isSome) |>
        should equal [0x02;]
        
    // we thus know the last byte in the *decoded* data is (0x02 ^ 0x01) = 0x03.
    
    // so -- how do we generalize this? (explained using 4 byte blocks...)
    // to attack the LAST byte, we try to make the decoded content to end with 0x01 by XORing the penultimate block with
    // 000000XX until we get an OK response. We then retry with 0000ffXX to find out which one the 'correct' one is.
    // The last byte in the original decrypted content is then (0x01 ^ 0xXX)
    //
    // For the byte before that, it's the same concept, but we now try with a two-byte padding.\
    // The final byte to XOR with is given by (dec ^ 0x02)  (i.e., 0xXX ^ (0x02 ^ 0x01)) -> call this YY
    // we then attack by XORing with 0000XXYY until the decoded content ends with 0202
    // there is no chance for confusion here; the last 0x02 byte will guarantee that only the XX resulting in a 0x02
    // decoded value is correct.
    // Repeat for every subsequent byte.
    // Then, cut off the last block and try with the previous block.
    //
    // Ok, but how does this then work for the FIRST block? Remember that the IV is effectively the 'first block'.
    // So instead of bit-flipping the first block, bitflip the IV. Or, better: zero the IV and use the IV as
    // first block:
    
    let short_content = "0123456789abcd" |> Ascii.charToByte
    let short_enc = Aes.encryptCbcPkcs7 key iv short_content
    let zero_IV = Seq.replicate 16 0
    let combined_dec = Aes.decryptCbcPkcs7 key zero_IV (Seq.append iv short_enc)
    combined_dec |> Option.get |> Seq.skip 16 |> Ascii.byteToChars |> should equal "0123456789abcd"
    
    let oracle = Aes.decryptCbcPkcs7 key
    
    let decrypted = decrypt_last_block oracle iv short_enc
    decrypted |> Ascii.byteToChars |> should equal "0123456789abcd??"
    
    // rinse and repeat to do the entire thing
    short_enc |> decrypt_all oracle iv |> Ascii.byteToChars |> should equal "0123456789abcd??"
    
    let pad1_enc =  content_pad1 |> Aes.encryptCbcPkcs7 key iv
    pad1_enc |> decrypt_all oracle iv |> Ascii.byteToChars |> should equal "0123456789abcdef0123456789abcde?"
        
        
[<Test>]
let challenge17 () =
    let key = Random.randomBytes 16
    let iv = Random.randomBytes 16
    
    let challenge = @"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93".Split('\n') |> Random.choose |> Base64.base64ToByte

    let enc_challenge = challenge |> Aes.encryptCbcPkcs7 key iv

    let oracle = Aes.decryptCbcPkcs7 key

    enc_challenge |> decrypt_all oracle iv |> Padding.strip_padding |> Option.get |> should equal challenge

[<Test>]
let testCtrMode () =
    Aes.genCtr |> Seq.skip 65534 |> Seq.head |> should equal [0xfe; 0xff; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00]
    
    let nonce = seq { 0 .. 1 .. 7 }
    let blockSize = 16
    Aes.genCtrStream id nonce |> Seq.skip (blockSize * 65534) |> Seq.take blockSize |> should equal [
        0x00; 0x01; 0x02; 0x03; 0x04; 0x05; 0x06; 0x07;
        0xfe; 0xff; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00;
    ]

[<Test>]
let challenge18 () =
    let enc = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==" |> Base64.base64ToByte
    let key = "YELLOW SUBMARINE" |> Ascii.charToByte
    let nonce = Seq.replicate 8 0
    
    let dec = enc |> Aes.decryptCtr key nonce
    
    dec |> Ascii.byteToChars |> should equal "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby I"
    
    let newKey = Random.randomBytes 16
    let newNonce = Random.randomBytes 8
    
    let enc1 = "s" |> Ascii.charToByte |> Aes.encryptCtr newKey newNonce
    
    enc1 |> Seq.length |> should equal 1
    
    enc1 |> Aes.decryptCtr newKey newNonce |> Ascii.byteToChars |> should equal "s"

    let enc2 = "abcdefghijklmnopqrstuvwxyz" |> Ascii.charToByte |> Aes.encryptCtr newKey newNonce
    
    enc2 |> Seq.length |> should equal 26
    enc2 |> Aes.decryptCtr newKey newNonce |> Ascii.byteToChars |> should equal "abcdefghijklmnopqrstuvwxyz"
    enc2 |> Seq.skip 3 |> Aes.encryptCtrOffset 3 newKey newNonce |> Ascii.byteToChars |> should equal "defghijklmnopqrstuvwxyz"


[<Test>]
let challenge19 () =
    let key = Random.randomBytes 16
    let nonce = Random.randomBytes 8
    let ciphertexts = File.readChallengeData "19.txt" |> Seq.map (Base64.base64ToByte >> Aes.encryptCtr key nonce)
    
    // we can now attack the ciphertexts as in challenge 6: every first byte is XORed with the same key byte, every
    // second byte is XORed with the same key byte, etc.
    let decrypted = ciphertexts |> Seq.transpose |> Seq.map set1.crackXor
    let keybytes = decrypted |> Seq.map (fun (_, k, _) -> k)
    
    ciphertexts |> Seq.map (Seq.pairxor keybytes >> Ascii.byteToChars) |> Seq.last 1 |> Seq.head |> should equal "a terrible beauty is born. "
    
[<Test>]
let challenge20 () =
    // same exercise but different text values
    let key = Random.randomBytes 16
    let nonce = Random.randomBytes 8
    let ciphertexts = File.readChallengeData "20.txt" |> Seq.map (Base64.base64ToByte >> Aes.encryptCtr key nonce)
    
    let decrypted = ciphertexts |> Seq.transpose |> Seq.map set1.crackXor
    let keybytes = decrypted |> Seq.map (fun (_, k, _) -> k)
    
    ciphertexts |> Seq.map (Seq.pairxor keybytes >> Ascii.byteToChars) |> Seq.last 1 |> Seq.head |> should equal "and we outta here / Yo, what happened to peace? / Peace?"


[<Test>]
let testMT () =
    Random.mt19937 (Random.mtInit.Seed 123u) |> Seq.take 10 |> should equal [
        2991312382u;
        3062119789u;
        1228959102u;
        1840268610u;
         974319580u;
        2967327842u;
        2367878886u;
        3088727057u;
        3090095699u;
        2109339754u;
    ]
    
[<Test>]
let challenge22 () =
    let wait1 = Random.randomInt 40 1000
    let wait2 = Random.randomInt 40 1000
    
    let ts0 = int (DateTime.UtcNow - DateTime.UnixEpoch).TotalSeconds
    let ts1 = ts0 + wait1
    
    let randomValue = Random.mt19937 (Random.mtInit.Seed (uint ts1)) |> Seq.head
    
    let ts2 = ts1 + wait2
    
    // now we can iterate over all 'realistic' seed values
    let seedAttempts = seq { (ts2 - 3600) .. 1 .. ts2 }
    
    let foundSeed = seedAttempts |> Seq.where (uint >> Random.mtInit.Seed >> Random.mt19937 >> Seq.head >> (=) randomValue) |> Seq.head
    
    foundSeed |> should equal ts1
    
// positive shift is shift left, negative is shift right
let untemper shift andval value =
    let value_bits = Bits.binarize32 value |> Seq.toArray
    let andval_array = Bits.binarize32 andval |> Seq.toArray
    
    //value_bits |> Seq.map string |> String.concat "" |> printsn
    //andval_array |> Seq.map string |> String.concat "" |> printsn

    let folder (state: int array) index =
        let shifted_bit = state |> Array.tryItem (index + shift) |> Option.defaultValue 0
        let bit = value_bits[index] ^^^ (shifted_bit &&& andval_array[index])
        //state |> Seq.map string |> String.concat "" |> printsn
        //printfn $"state[{index}] = {value_bits[index]} ^ ({state[index + shift]} & {andval_array[index]}) = {bit}"
        state |> Array.withreplace index bit

    let initialArray = Array.replicate 32 0
    let order = if shift > 0 then seq { 31 .. -1 .. 0 } else seq { 0 .. 1 .. 31 }
    let bits_recovered = order |> Seq.fold folder initialArray
    bits_recovered |> Bits.unbinarize


[<Test>]
let untemperTryout() =
    let testValues = Seq.initInfinite (fun _ -> Random.randomUintFullRange) |> Seq.take 100
        
    let (u, d) = (11, 0xFFFFFFFFu)
    let (s, b) = (7, 0x9D2C5680u)
    let (t, c) = (15, 0xEFC60000u)
    let l = 18

    let mt1 y = y ^^^ ((y >>> u) &&& d)
    let mt2 y = y ^^^ ((y <<< s) &&& b)
    let mt3 y = y ^^^ ((y <<< t) &&& c)
    let mt4 y = y ^^^ (y >>> l)
    
    let mt = mt1 >> mt2 >> mt3 >> mt4       

    // l is 18, so mt4 does:
    // y                   = [abcdefghijklmnopqrstuvwxyzABCDEF]
    // y >> 18             = [000000000000000000abcdefghijklmn]
    // y' = (y ^ (y >> 18) = [abcdefghijklmnopqr??????????????]
    // so to invert, we take the same rightshift
    // y' >> 18            = [000000000000000000abcdefghijklmn]
    // and apply the same XOR to recover the original bits
    // in other words,
    
    let unmt4 = mt4
    testValues |> Seq.map (mt4 >> unmt4) |> should equal testValues  
    
    // for mt3, t=15, c=[11101111110001100000000000000000]
    // --> y ^^^ ((y <<< t) &&& c)
    // y                   = [abcdefghijklmnopqrstuvwxyzABCDEF]
    // y << 15             = [pqrstuvwxyzABCDEF000000000000000]
    // c                   = [11101111110001100000000000000000]
    // (y << 15) & c       = [pqr0tuvwxy000CD00000000000000000]
    // y'                  = [???d??????klm??pqrstuvwxyzABCDEF]
    // same here: the bits we need are intact, so
    let unmt3 = mt3
    testValues |> Seq.map (mt3 >> unmt3) |> should equal testValues
    
    // for mt2 y = y ^^^ ((y <<< s) &&& b)
    // let's be lazy and just assume the same approach works
    testValues |> Seq.map (mt2 >> mt2) |> should not' (equal testValues)
    
    // haha, just kidding.
    // s = 7 and b = [10011101001011000101011010000000]
    // y                   = [abcdefghijklmnopqrstuvwxyzABCDEF]
    // y << 7              = [hijklmnopqrstuvwxyzABCDEF0000000]
    // b                   = [10011101001011000101011010000000]
    // (y << 7) & b        = [h00klm0o00r0tu000y0A0CD0F0000000]
    // y'                  = [?bc???g?ij?l??opq?s?u??x?zABCDEF]
    // y' << 7             = [?ij?l??opq?s?u??x?zABCDEF0000000]
    // (y' << 7) & b       = [?00?l?0o00?0?u000?0A0CD0F0000000]
    // y' ^ ((y' << 7) & b)= [?bc?e?ghij?l?nopq?stuvwxyzABCDEF]
    // err..
    // let's approach this from a different direction: yprime[i] = ...
    // for every bit i
    // y'[i] = y[i] ^ (y[i + 7] & b[i])
    // where we know that y[32] and higher is a 0.
    // so working from right to left, we have
    // y'[31] = y[31] ^ (y[38] & b[31]) = y[31] --> y[31] = y'[31]
    // y'[24] = y[24] ^ (y[31] & b[24]) --> we KNOW y[31] from the previous statement!
    // so we can build the value from right to left without any guessing.
   
    // first test with mt3
    0x12345678u |> mt3 |> should equal 0x39305678u
    0x39305678u |> unmt3 |> should equal 0x12345678u
    0x39305678u |> untemper t c |> should equal 0x12345678u
    
    // now with mt2
    0x12345678u |> mt2 |> untemper s b |> should equal 0x12345678u
    
    // mt4 -- negative shift?
    0x12345678u |> mt4 |> untemper -l 0xFFFFFFFFu |> should equal 0x12345678u
    
    // mt1 -- also a negative shift
    0x12345678u |> mt1 |> untemper -u d |> should equal 0x12345678u
    
    // ok, so what do we have?
    let unmt1 = untemper -u d
    let unmt2 = untemper s b
    let unmt3 = untemper t c
    let unmt4 = untemper -l 0xFFFFFFFFu
    let unmt = unmt4 >> unmt3 >> unmt2 >> unmt1
    
    testValues |> Seq.map mt |> Seq.map unmt |> should equal testValues
    
[<Test>]
let testBinarize32 () =
    0b10000000u |> Bits.binarize8 |> Seq.map string |> String.concat "" |> should equal "10000000"
    0b10011101001011000101011010000000u |> Bits.binarize32 |> Seq.map string |> String.concat "" |>
        should equal "10011101001011000101011010000000"
        
[<Test>]
let testArrayReplace () =
    {0 .. 1 .. 9} |> Seq.toArray |> Array.withreplace 4 1234 |> should equal [| 0; 1; 2; 3; 1234; 5; 6; 7; 8; 9 |]
    
let untemperMt =
    let (u, d) = (11, 0xFFFFFFFFu)
    let (s, b) = (7, 0x9D2C5680u)
    let (t, c) = (15, 0xEFC60000u)
    let l = 18
    let unmt1 = untemper -u d
    let unmt2 = untemper s b
    let unmt3 = untemper t c
    let unmt4 = untemper -l 0xFFFFFFFFu
    unmt4 >> unmt3 >> unmt2 >> unmt1
    
[<Test>]
let challenge23 () =
    let stateSize = 624
    let generator = 0u |> Random.mtInit.Seed |> Random.mt19937
    let randomValues = generator |> Seq.take 1000
    
    let firstOutputs = randomValues |> Seq.take stateSize
    let tenAfter = randomValues |> Seq.skip stateSize |> Seq.take 10
    
    let regeneratedState = firstOutputs |> Seq.map untemperMt |> Seq.toArray
    
    let newGenerator = Random.mt19937 (Random.mtInit.State (regeneratedState, stateSize))
    
    newGenerator |> Seq.take 10 |> should equal tenAfter

let mtcipher seed =
    Random.mt19937 (Random.mtInit.Seed seed) |> Seq.collect (fun x ->
        seq {0 .. 8 .. 24 } |> Seq.map (fun shift -> int ((x >>> shift) % 256u)))

let mtcipher_enc seed value = Seq.pairxor value (mtcipher seed)
let mtcipher_dec = mtcipher_enc

[<Test>]
let challenge24_play () =
    let seed = uint (Random.randomInt 0 65535)
    let enc = "Hello world" |> Ascii.charToByte |> mtcipher_enc seed

    enc |> Seq.length |> should equal 11
              
    let dec = enc |> mtcipher_dec seed |> Ascii.byteToChars
    dec |> should equal "Hello world"

[<Test>]
let challenge24 () =
    let seed = uint (Random.randomInt 0 65535)
    let plaintext = "AAAAAAAAAAAAAA" |> Ascii.charToByte
    
    let postfix = "My secret content" |> Ascii.charToByte
    let prefix = Random.randomBytes (Random.randomInt 5 10)
    let enc = Seq.concat [prefix; plaintext; postfix] |> mtcipher_enc seed
    
    // to attack, try all 65535 valid seeds using a string with just As
    // and see when we get sufficient overlap
    let overlapFactor a b = Seq.zip a b |> Seq.where ((<||) (=)) |> Seq.length
    
    let manyAs = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" |> Ascii.charToByte
    
    let found_seed = {0u .. 1u .. 65535u} |> Seq.maxBy (fun seed -> mtcipher_enc seed manyAs |> overlapFactor enc)
    
    printfn "Found text: %s" (enc |> mtcipher_dec found_seed |> Ascii.byteToChars) 
    
    found_seed |> should equal seed

    // the second part is just challenge 22 again?