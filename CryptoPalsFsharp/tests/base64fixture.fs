module Base64fixture

open NUnit.Framework

[<Test>]
let SingleByte () =
    Assert.AreEqual("/w==", [0xff] |> Base64.byteToBase64)
    
[<Test>]
let TwoBytes () =
    Assert.AreEqual("qrs=", [0xaa; 0xbb] |> Base64.byteToBase64)
    
[<Test>]
let ThreeBytes () =
    Assert.AreEqual("qrvM", [0xaa; 0xbb; 0xcc] |> Base64.byteToBase64)