module set1

open System.Security.Cryptography
open NUnit.Framework
open FsUnit
open cryptopals

let xor = (^^^)

[<Test>]
let challenge1 () = // Convert hex to base64
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    let b64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    
    hex |> Hex.hexToByte |> Base64.byteToBase64 |> should equal b64
    b64 |> Base64.base64ToByte |> Hex.byteToHex |> should equal hex

[<Test>]
let challenge2 () = // Fixed XOR
    let hex1 = "1c0111001f010100061a024b53535009181c" |> Hex.hexToByte
    let hex2 = "686974207468652062756c6c277320657965" |> Hex.hexToByte
    
    Seq.pairxor hex1 hex2 |>
    Hex.byteToHex |>
    should equal "746865206b696420646f6e277420706c6179"


let decodeXor = fun data key -> data |> (Seq.map (fun byte -> byte ^^^ key))

let crackXorOptions keys bytes =
    keys |> Seq.map (decodeXor bytes) |>
            Seq.map (Ascii.byteToChars)


[<Test>]
let testCountPrintable () =
    Ascii.countprintable "abcd\x00\x01\x02" |> should equal 4 

let crackXor bytes =
    let keys = [0x00..0xff] |> List.map int
    
    let keyIndex, score =
       crackXorOptions keys bytes |>
       Seq.map Ascii.countprintable |>
       Seq.indexed |>
       Seq.maxBy snd

    let key = keys.[keyIndex]
    
    (score, key, key |> decodeXor bytes |> Ascii.byteToChars)

[<Test>]
let challenge3 () = // Single-byte XOR cipher
    let hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736" |> Hex.hexToByte
    
    let score, key, decrypted = crackXor hex
    decrypted |> should equal "Cooking MC's like a pound of bacon"

[<Test>]
let challenge4 () = // Detect single-character XOR
    let lines = File.readChallengeData "4.txt" |> List.map Hex.hexToByte 
        
    let score x = List.ofSeq x |> List.map (fun c -> if Ascii.isprintable c then 1 else 0) |> List.sum     
    
    let keys = [0x00..0xff] |> List.map int
    
    lines |> Seq.collect (crackXorOptions keys) |>
             Seq.maxBy (score) |>
             should equal "Now that the party is jumping\n"
       
    let (s, k, r) = lines |> List.map crackXor |> List.maxBy (fun (score, _, _) -> score)
    s |> should equal (String.length "Now that the party is jumping")  // newline is considered non-printable
    k |> should equal 0x35
    r |> should equal "Now that the party is jumping\n"

let repeatkey_list (key: list<'T>) = Seq.initInfinite (fun index -> key[index % key.Length])
let repeatkey (key: seq<'T>) = key |> List.ofSeq |> repeatkey_list

[<Test>]
let testRepeat () =
    "ABC" |> Seq.map Ascii.charToVal |> repeatkey |> Seq.take 3 |> Seq.map Ascii.valToChar |> should equal "ABC"
    "ABC" |> Seq.map Ascii.charToVal |> repeatkey |> Seq.take 4 |> Seq.map Ascii.valToChar |> should equal "ABCA"
    "ABC" |> Seq.map Ascii.charToVal |> repeatkey |> Seq.take 6 |> Seq.map Ascii.valToChar |> should equal "ABCABC"

let xorRepeating key content =
    Seq.zip content (key |> repeatkey) |> Seq.map((<||) xor)

[<Test>]
let challenge5 () = // Implement repeating-key XOR
    let content = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal" |> Seq.map Ascii.charToVal
    let key = "ICE" |> Seq.map Ascii.charToVal
    
    let encrypted = content |> xorRepeating key
    
    encrypted |> Hex.byteToHex |> should equal "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

let hammingdistance (a: seq<int>) (b: seq<int>) =
    Seq.zip a b |>
    Seq.map((<||) xor) |>
    Bits.bytesToBits |>
    Seq.sum
    
[<Test>]
let test_hammingdistance () =
    hammingdistance ("this is a test" |> Seq.map Ascii.charToVal) ("wokka wokka!!!" |> Seq.map Ascii.charToVal) |>
    should equal 37

[<Test>]
let testGroupBy () =
    let input = [ (1, 0); (2, 1); (3, 0); (4, 1) ]
    input |> Seq.groupBy snd |> should equal [ (0, [ (1,0); (3,0) ]); (1, [ (2,1); (4,1) ]) ]

// let grouper size input =
//     Seq.zip input (seq { 0 .. 1 .. (size - 1) } |> repeatkey) |>  // [ (input[i], i % size); ...]
//     Seq.groupBy snd |>                                            // [ (0, [ (input[0], 0); (input[0 + size], 0); ... ]); ... ]
//     Seq.map snd |>                                                // [ [ (input[0], 0); (input[0 + size], 0); ... ], ... ];
//     Seq.map (Seq.map fst)                                         // [ [ input[0]; input[0 + size], ... ], ... ]
    
let grouper size input =
    let modSize v = v % size
    input |> Seq.indexed |> Seq.groupBy (fst >> modSize) |> Seq.map snd |> Seq.map (Seq.map snd)

[<Test>]
let testGrouper () =
    seq { 10 .. 1 .. 15 } |> grouper 1 |> should equal [ [10; 11; 12; 13; 14; 15 ]; ]
    seq { 10 .. 1 .. 15 } |> grouper 2 |> should equal [ [10; 12; 14]; [11; 13; 15] ]
    seq { 10 .. 1 .. 15 } |> grouper 3 |> should equal [ [10; 13]; [11; 14]; [12; 15] ]
    seq { 10 .. 1 .. 15 } |> grouper 4 |> should equal [ [10; 14]; [11; 15]; [12;]; [13;] ]
    
let crackXorWithSize keySize bytes =
    let grouped = grouper keySize bytes
    let cracked_key = grouped |> Seq.map (Seq.toList >> crackXor >> (fun (_, k, _) -> k)) |> Seq.toList
    let decoded = xorRepeating cracked_key bytes |> Ascii.byteToChars
    (Ascii.countprintable decoded, cracked_key, decoded)

[<Test>]
let challenge6 () = // Break repeating-key XOR
    let bytes = File.readChallengeData "6.txt" |> String.concat "" |> Base64.base64ToByte
    
    // first determine the keysize
    let keysizes = { 2 .. 1 .. 40 }
    
    let fldiv x y = (double x) / (double y)
    let ks_hamming ks shift = fldiv (hammingdistance (bytes |> Seq.skip shift |> Seq.take ks) (bytes |> Seq.skip (ks + shift) |> Seq.take ks)) ks
    let ks_hamming ks = (ks_hamming ks 0) + (ks_hamming ks ks) + (ks_hamming ks (2*ks)) + (ks_hamming ks (3*ks))
    
    let keysizes_likely = keysizes |>
                          Seq.map ( fun (ks: int) -> (ks, ks_hamming ks)) |>
                          Seq.sortBy snd |>
                          Seq.map fst |>
                          Seq.take 3
    
    keysizes_likely |> should equal [ 2; 5; 29 ]
    
    // for ks in keysizes_likely do
    //     let grouped = grouper ks bytes
    //     let cracked_key = grouped |> Seq.map (Seq.toList >> crackXor >> (fun (_, k, _) -> k)) |> Seq.toList
    //     let decoded = xorRepeating cracked_key bytes |> Seq.take 32 |> Ascii.byteToChars
    //     printfn $"{ks}, {cracked_key |> Hex.byteToHex}, {decoded}"
    
    let (score, cracked_key, decoded) = keysizes_likely |> Seq.map (fun ks -> crackXorWithSize ks bytes) |> Seq.maxBy (fun (s, _, _) -> s)
    
    printfn $"{decoded}"

    cracked_key |> Hex.byteToHex |> should equal "5465726d696e61746f7220583a204272696e6720746865206e6f697365"
    decoded[0..32] |> should equal "I'm back and I'm ringin' the bell"


// AES in ECB mode
[<Test>]
let challenge7 () =
    let enc = File.readChallengeData "7.txt" |> String.concat "" |> Base64.base64ToByte
    let key = "YELLOW SUBMARINE" |> Ascii.charToByte
    
    let decrypted = Aes.decryptEcb PaddingMode.PKCS7 key enc
    
    decrypted[0..32] |> should equal "I'm back and I'm ringin' the bell"
    
    let decrypted_own = Aes.decryptEcbPkcs7 key enc
    decrypted_own[0..32] |> should equal "I'm back and I'm ringin' the bell"
    
    let encrypted_own = Aes.encryptEcbPkcs7 key decrypted_own
    encrypted_own |> should equal enc

[<Test>]
let testSplitBlocks () =
    let input = {100 .. 1 .. 163}
    input |> Seq.length |> should equal 64
    
    input |> Seq.splitBlocks 16 |> should equal [{100 .. 1 .. 115}; {116 .. 1 .. 131}; {132 .. 1 .. 147}; {148 .. 1 .. 163}]
    input |> Seq.splitBlocks 15 |> should equal [{100 .. 1 .. 114}; {115 .. 1 .. 129}; {130 .. 1 .. 144}; {145 .. 1 .. 159}; {160 .. 1 .. 163}]



[<Test>]
let testCountDuplicates () =
    [0; 1; 2; 3; 4] |> Seq.countDuplicates |> should equal 0
    [0; 0; 1; 2; 3; 4] |> Seq.countDuplicates |> should equal 1
    [0; 0; 0; 1; 2; 3; 4] |> Seq.countDuplicates |> should equal 2
    [0; 0; 1; 1; 2; 3; 4] |> Seq.countDuplicates |> should equal 2
    
    ["alpha"; "alpha"; "beta"] |> Seq.countDuplicates |> should equal 1
    
    // lists, arrays are compared by value
    [[0; 0]; [0; 0]; [0; 1]] |> Seq.countDuplicates |> should equal 1
    [ [| 0; 0 |]; [| 0; 0 |]; [| 0; 1 |] ] |> Seq.countDuplicates |> should equal 1
    
    // sequences are compared by ref
    [{0 .. 1 .. 2}; {0 .. 1 .. 2}] |> Seq.countDuplicates |> should equal 0
    [{0 .. 1 .. 2}; {0 .. 1 .. 2}] |> Seq.map Seq.toArray |> Seq.countDuplicates |> should equal 1

let tupFn fn input = (input, fn input)

// Detect AES in ECB mode
[<Test>]
let challenge8 () =
    let enc = File.readChallengeData "8.txt" |> Seq.map Hex.hexToByte

    let suspicious = enc |> Seq.map (tupFn (Seq.splitBlocks 16 >> Seq.map Seq.toArray >> Seq.countDuplicates)) |> Seq.sortBy snd |> Seq.rev |> Seq.take 5
    
    suspicious |> Seq.map (fun (v, c) -> $"{c}: {v |> Hex.byteToHex}") |> String.concat "\n" |> printfn "%s"
    
    let very_suspicious = suspicious |> Seq.head
    
    very_suspicious |> snd |> should equal 3  // 3 repeated blocks
    very_suspicious |> fst |> Hex.byteToHex |> fun x -> x[0..31] |> should equal "d880619740a8a19b7840a8a31c810a3d"
