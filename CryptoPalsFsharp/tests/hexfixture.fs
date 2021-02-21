module HexFixture

open NUnit.Framework
open FsCheck
open FsUnit
open FsCheck.NUnit

type ByteInt = ByteInt of int with
  static member op_Explicit(ByteInt i) = i
  
type Generators =
    static member ByteInt() = 
        Gen.choose(0, 255) |> Gen.map ByteInt |> Arb.fromGen

module tests =
    [<Property(Arbitrary=[| typeof<Generators> |])>]
    let ``Can round-trip to hex and back`` (xs:list<ByteInt>) =
        let input = List.map int xs
        input |> Hex.byteToHex |> Hex.hexToByte |> should equal input

[<Test>]
let ZeroByte () =
    [0x00] |> Hex.byteToHex |> should equal "00"
