module Base64fixture

open NUnit.Framework
open FsUnit

[<Test>]
let SingleByte () =
    [0xff] |> Base64.byteToBase64 |> should equal "/w=="
    
[<Test>]
let TwoBytes () =
    [0xaa; 0xbb] |> Base64.byteToBase64 |> should equal "qrs="
    
[<Test>]
let ThreeBytes () =
    [0xaa; 0xbb; 0xcc] |> Base64.byteToBase64 |> should equal "qrvM"