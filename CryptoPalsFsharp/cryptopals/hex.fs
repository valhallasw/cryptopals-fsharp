module Hex
open cryptopals

let private hex = Array.ofSeq "0123456789abcdef"
let swap (x, y) = (y, x)
let private invertedLookup = hex |> Array.indexed |> Array.map swap |> Map

let private valToNibble i = Array.item i hex
let private nibbleToVal i = invertedLookup.Item i
    
let hexToByte (hex: string):bytearray = 
    List.ofSeq hex |> List.chunkBySize 2 |> List.map (List.map nibbleToVal) |> List.map (List.fold ((*) 16 >> (+)) 0)

let byteToHex (data: bytearray): string =
    data |> List.map (fun i -> [i / 16; i % 16]) |> List.collect (List.map valToNibble) |> List.map string |> String.concat ""