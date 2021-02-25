module set1

open NUnit.Framework
open FsUnit

[<Test>]
let challenge1 () =
    "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d" |>
        Hex.hexToByte |>
        Base64.byteToBase64 |>
        should equal "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

[<Test>]
let challenge2 () =
    let hex1 = "1c0111001f010100061a024b53535009181c" |> Hex.hexToByte
    let hex2 = "686974207468652062756c6c277320657965" |> Hex.hexToByte
    
    List.zip hex1 hex2 |>
    List.map((<||) (^^^))|>
    Hex.byteToHex |>
    should equal "746865206b696420646f6e277420706c6179"
    
[<Test>]
[<Explicit>]
let challenge3 () =
    let hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736" |> Hex.hexToByte
    let key = 0x01
    Assert.Fail()
