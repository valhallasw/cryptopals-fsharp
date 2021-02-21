module Hex
open cryptopals

let private nibbleToVal v =
    match v with
    | '0' -> 0
    | '1' -> 1
    | '2' -> 2
    | '3' -> 3
    | '4' -> 4
    | '5' -> 5
    | '6' -> 6
    | '7' -> 7
    | '8' -> 8
    | '9' -> 9
    | 'a' -> 10
    | 'b' -> 11
    | 'c' -> 12
    | 'd' -> 13
    | 'e' -> 14
    | 'f' -> 15
    | _ -> invalidArg (nameof v) (sprintf "%c is not have a valid value" v)
    
let hexToByte (hex: string):bytearray = 
    List.ofSeq hex |> List.chunkBySize 2 |> List.map (List.map nibbleToVal) |> List.map (List.fold ((*) 16 >> (+)) 0)
    
let byteToHex (data: bytearray): string =
    data |> List.map (sprintf "%02x") |> String.concat ""