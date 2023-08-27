module ch41

open System
open System.Collections.Generic
open System.Net
open System.Numerics
open System.Security.Cryptography
open System.Threading
open Microsoft.FSharp.Collections
open Microsoft.FSharp.Control
open NUnit.Framework
open FsUnit
open cryptopals


type Server(rsa: rsa.Rsa) =
    let mutable messages = set<bigint> []
    
    member this.decrypt (message: bigint) =
        if (messages |> Set.contains message) 
        then None
        else
            messages <- messages.Add message
            Some (rsa.decrypt message)

[<Test>]
let challenge41() =
    let rsa_obj = rsa.Rsa()
    let server = Server(rsa_obj)
    
    let c = "MySecretMessage" |> Ascii.charToByte |> Seq.toBigintBe |> rsa_obj.encrypt
    server.decrypt c |> ignore
    
    // can't decrypt a second time
    server.decrypt c |> should equal None
    
    // however...
    let (e, n) = rsa_obj.pub
    let inline ( |^| ) x y = BigInteger.ModPow(x, y, n)
    
    let s = bigint 3
    let c' = ((s |^| e) * c) % n
    
    let p' = c' |> server.decrypt |> Option.get
    
    let sinv = rsa.invmod s n |> Option.get
    let p = (p' * sinv) % n
    
    p |> Seq.fromBigintBe |> Ascii.byteToChars |> should equal "MySecretMessage"


type ProcessingState = Error | Begin | Prefix0 | Prefix1 | Prefixff | Hash

type ParsingResult = { Hash: seq<int> }

let processchar state char =
    match state with
        | Error -> (None, Error)
        | Begin -> match char with
                   | 0x00 -> (None, Prefix0)
                   | 0x01 -> (None, Prefix1)  // 0x00 prefix has no meaning in integers...
                   | _ -> (None, Error)
        | Prefix0 -> match char with
                     | 0x01 -> (None, Prefix1)
                     | _ -> (None, Error)
        | Prefix1 -> match char with
                     | 0xff -> (None, Prefixff)
                     | _ -> (None, Error)
        | Prefixff -> match char with
                      | 0xff -> (None, Prefixff)
                      | 0x00 -> (None, Hash)
                      | _ -> (None, Error)
        | Hash -> (Some char, Hash)

let printMapFolder method state char =
    let (res, newstate) = method state char
    printfn $"%02x{char}: {state} -> {newstate} with {res}"
    (res, newstate)
    
[<Test>]
let testprocesschar() =
    let message = "0001ffffffff000102030405060708" |> Hex.hexToByte
    let (s, state) = message |> Seq.mapFold (printMapFolder processchar) Begin
    
    state |> should equal Hash
    
    let hash = s |> Seq.collect (Option.map Seq.singleton >> Option.defaultValue Seq.empty)
    hash |> Hex.byteToHex |> should equal "0102030405060708"

let get_hash_from_signature (rsa: rsa.Rsa) signature =
    let dec = rsa.encrypt signature |> Seq.fromBigintBe
    let (s, state) = dec |> Seq.mapFold processchar Begin
    
    match state with
        | Hash -> Some (s |> Seq.collect (Option.map Seq.singleton >> Option.defaultValue Seq.empty))
        | _ -> None

let sign (rsa: rsa.Rsa) message =
    let hash = Sha256.hash message
    let hash_size = hash |> Seq.length
    let min_size = rsa.pub |> snd |> Seq.fromBigintBe |> Seq.length
    
    let padded_hash = Seq.concat [
        0x00 |> Seq.singleton
        0x01 |> Seq.singleton
        0xff |> Seq.replicate (min_size - hash_size - 3)
        0x00 |> Seq.singleton
        hash
    ]
    
    let message = padded_hash |> Seq.toBigintBe
    rsa.decrypt message

let bad_signature_checker (rsa: rsa.Rsa) message signature =
    let signed_hash = get_hash_from_signature rsa signature |> Option.defaultValue Seq.empty |> Seq.take 32
    let hash = Sha256.hash message
    
    Seq.allEqual signed_hash hash

[<Test>]
let challenge42() =
    let rsa_obj = rsa.Rsa()
    let message = "Hello, this is a signed message!" |> Ascii.charToByte
    
    let signature = sign rsa_obj message
    bad_signature_checker rsa_obj message signature |> should equal true
    
    let faked_message = "hi mom" |> Ascii.charToByte
    bad_signature_checker rsa_obj faked_message signature |> should equal false
    
    let hash = Sha256.hash faked_message
    
    // the generated value (in base-2) will look something like
    // 00000001 11111111 00000000 aaaaaaaa ..... tttttttt 00000000 ... 00000000
    // the number of bits in n = p*q is 1024 (128 bytes)
    // so we are OK as long as the total number of bits is less than that
    // we pad with 93 0x00 bytes, thus we have a (2+32+93) = 127 byte number;
    // just low enough to not "turn over" through the modulus    
    printfn "n = %s" (rsa_obj.pub |> snd |> Seq.fromBigintBe |> Hex.byteToHex)
    
    let padded_hash = Seq.concat [
        0x01 |> Seq.singleton
        0xff |> Seq.singleton
        0x00 |> Seq.singleton
        hash
        0x00 |> Seq.replicate 93
    ]
    
    let faked_signature = set5.CubicRoot (padded_hash |> Seq.toBigintBe)
    
    let validated = rsa_obj.encrypt faked_signature |> Seq.fromBigintBe
    
    // we have a malformed message, but the first bytes are correct
    validated |> Hex.byteToHex |> should not' (equal (padded_hash |> Hex.byteToHex))
    validated |> Seq.take (3+32) |> Hex.byteToHex |> should equal (padded_hash |> Seq.take (3+32) |> Hex.byteToHex)
    
    bad_signature_checker rsa_obj faked_message faked_signature |> should equal true
    ()

    