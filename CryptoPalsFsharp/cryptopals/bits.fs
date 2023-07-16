module Bits

open System

let rec private binarizer (max: uint) (n: uint) =
    if max = 0u then []
    elif n >= max then ([ 1 ] @ (binarizer (max / 2u) (n - max)))
    else ([ 0 ] @ (binarizer (max / 2u) (n)))

let binarize8 = binarizer 128u
let binarize6 = binarizer 32u

let binarize32 = binarizer (UInt32.MaxValue / 2u + 1u)

let unbinarize: seq<int> -> uint = Seq.fold (fun c v -> 2u * c + (uint v)) 0u //or... ((*) 2 >> (+)) 0

let bytesToBits: seq<int> -> seq<int> = Seq.map uint >> Seq.collect binarize8 
