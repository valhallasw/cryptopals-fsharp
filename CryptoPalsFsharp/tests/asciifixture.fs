module Asciifixture

open NUnit.Framework
open FsUnit

[<Test>]
let SpaceByte () =
    [32] |> Ascii.byteToChars |> should equal " "
    " " |> Ascii.charToByte |> should equal [32]

[<Test>]
let aByte () =
    [97] |> Ascii.byteToChars |> should equal "a"
    "a" |> Ascii.charToByte |> should equal [97]
    
[<Test>]
let boundaries () =
    [0; 255] |> Ascii.byteToChars |> should equal "??"

    

