module set1

open System.IO
open System.Reflection
open System.Resources
open NUnit.Framework
open FsUnit

let xor = (^^^)

[<Test>]
let challenge1 () = // Convert hex to base64
    "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d" |>
        Hex.hexToByte |>
        Base64.byteToBase64 |>
        should equal "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

[<Test>]
let challenge2 () = // Fixed XOR
    let hex1 = "1c0111001f010100061a024b53535009181c" |> Hex.hexToByte
    let hex2 = "686974207468652062756c6c277320657965" |> Hex.hexToByte
    
    Seq.zip hex1 hex2 |>
    Seq.map((<||) xor) |>
    Hex.byteToHex |>
    should equal "746865206b696420646f6e277420706c6179"


let decodeXor = fun data key -> data |> (List.map (fun byte -> byte ^^^ key))

let crackXorOptions keys bytes =
    keys |> List.map (decodeXor bytes) |>
            List.map (Ascii.byteToChars)

let isprintable v =
    let charval = v |> Ascii.charToVal

    (charval >= ('A' |> Ascii.charToVal) && charval <= ('Z' |> Ascii.charToVal)) ||
    (charval >= ('a' |> Ascii.charToVal) && charval <= ('z' |> Ascii.charToVal)) ||
    (charval = (' ' |> Ascii.charToVal))
        
let crackXor bytes =
    let keys = [0x00..0xff] |> List.map int
    
    let keyIndex, score =
       crackXorOptions keys bytes |>
       List.map (List.ofSeq) |>
       List.map (List.map (fun c -> if isprintable c then 1 else 0)) |>
       List.map (List.sum) |>
       List.indexed |>
       List.maxBy snd

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
        
    let score x = List.ofSeq x |> List.map (fun c -> if isprintable c then 1 else 0) |> List.sum     
    
    let keys = [0x00..0xff] |> List.map int
    
    lines |> List.collect (crackXorOptions keys) |>
             List.maxBy (score) |>
             should equal "Now that the party is jumping?"

let repeatkey_list (key: list<'T>) = Seq.initInfinite (fun index -> key[index % key.Length])
let repeatkey (key: seq<'T>) = key |> List.ofSeq |> repeatkey_list

[<Test>]
let testRepeat () =
    "ABC" |> Seq.map Ascii.charToVal |> repeatkey |> Seq.take 3 |> Seq.map Ascii.valToChar |> should equal "ABC"
    "ABC" |> Seq.map Ascii.charToVal |> repeatkey |> Seq.take 4 |> Seq.map Ascii.valToChar |> should equal "ABCA"
    "ABC" |> Seq.map Ascii.charToVal |> repeatkey |> Seq.take 6 |> Seq.map Ascii.valToChar |> should equal "ABCABC"

[<Test>]
let challenge5 () = // Implement repeating-key XOR
    let content = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal" |> Seq.map Ascii.charToVal
    let key = "ICE" |> Seq.map Ascii.charToVal
    
    let encryptedhex = Seq.zip content (key |> repeatkey) |>
        Seq.map((<||) xor) |>
        Hex.byteToHex
    
    encryptedhex |> should equal "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"