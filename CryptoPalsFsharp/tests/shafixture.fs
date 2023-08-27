module shafixture

open NUnit.Framework
open FsUnit
open cryptopals

[<Test>]
let testSha() =
    "The quick brown fox jumps over the lazy dog" |> Ascii.charToByte |> Sha1.hash |> Sha1.hashToHex |> should equal "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"

