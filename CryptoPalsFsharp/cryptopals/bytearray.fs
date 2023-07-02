namespace cryptopals

type bytearray = seq<int>

module Seq =
    let pairxor a b =
        Seq.zip a b |> Seq.map ((<||) (^^^))
        
    let splitBlocks size input =
        input |> Seq.indexed |> Seq.groupBy (fst >> fun x -> x / size) |> Seq.map (snd >> Seq.map snd)
    
    let countDuplicates input =
        input |> Seq.groupBy id |> Seq.map (snd >> Seq.length >> fun x -> x - 1) |> Seq.sum
        
    let maxDuplicated input =
        input |> Seq.groupBy id |> Seq.map (snd >> Seq.length >> fun x -> x - 1) |> Seq.max
        
    let last n xs = Seq.skip ((Seq.length xs) - n) xs