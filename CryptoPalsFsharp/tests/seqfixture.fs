module seqfixture

open NUnit.Framework
open FsUnit
open cryptopals

[<Test>]
let testAnyAll() =
    let s = seq { 0 .. 1 .. 10 }
    
    s |> Seq.any (fun x -> x > 0) |> should equal true
    s |> Seq.all (fun x -> x >= 0) |> should equal true
    s |> Seq.all (fun x -> x > 0) |> should equal false
    s |> Seq.any (fun x -> x > 10) |> should equal false

