module hmacfixture

open System.Security.Cryptography
open NUnit.Framework
open FsUnit
open cryptopals

[<Test>]
let testSha() =
    let key = "key" |> Ascii.charToByte
    let value = "The quick brown fox jumps over the lazy dog" |> Ascii.charToByte
                
    hmac.hmac_sha1 key value |> Hex.byteToHex |> should equal "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"

[<Test>]
let testOthers() = 
    let key = "key" |> Ascii.charToByte
    let value = "The quick brown fox jumps over the lazy dog" |> Ascii.charToByte

    let md5 value = (value |> Seq.map byte |> Seq.toArray) |> MD5.HashData |> Seq.map int
    let sha256 value = (value |> Seq.map byte |> Seq.toArray) |> SHA256.HashData |> Seq.map int
    let sha512 value = (value |> Seq.map byte |> Seq.toArray) |> SHA512.HashData |> Seq.map int
    
    hmac.compute md5 64 key value |> Hex.byteToHex |> should equal "80070713463e7749b90c2dc24911e275"
    hmac.compute sha256 64 key value |> Hex.byteToHex |> should equal "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
    hmac.compute sha512 128 key value |> Hex.byteToHex |> should equal "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a"

