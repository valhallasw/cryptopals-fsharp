module Hex
open cryptopals

let private hex = Array.ofSeq "0123456789abcdef"
let swap (x, y) = (y, x)
let private invertedLookup = hex |> Array.indexed |> Array.map swap |> Map

let private valToNibble i = Array.item i hex
let private nibbleToVal i = invertedLookup.Item i
    
let hexToByte (hex: string):bytearray = 
    hex |> Seq.chunkBySize 2 |> Seq.map (Seq.map nibbleToVal) |> Seq.map (Seq.fold ((*) 16 >> (+)) 0)

let byteToHex (data: seq<int>): string =
    data |> Seq.map (fun i -> [i / 16; i % 16]) |> Seq.collect (List.map valToNibble) |> Seq.map string |> String.concat ""