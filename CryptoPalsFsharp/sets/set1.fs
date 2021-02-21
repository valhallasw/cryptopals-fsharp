module set1

open System
open NUnit.Framework

[<Test>]
let challenge1 () =
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    let result =
        input |>
        Hex.hexToByte |>
        Base64.byteToBase64
    
    Assert.AreEqual("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t", result)

[<Test>]
let challenge2 () =
    let hex1 = "1c0111001f010100061a024b53535009181c" |> Hex.hexToByte
    let hex2 = "686974207468652062756c6c277320657965" |> Hex.hexToByte
    let result = List.zip hex1 hex2 |> List.map((<||) (^^^)) |> Hex.byteToHex
    
    Assert.AreEqual("746865206b696420646f6e277420706c6179", result)
    
[<Test>]
let challenge3 () =
    let hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736" |> Hex.hexToByte
    Assert.Fail()
