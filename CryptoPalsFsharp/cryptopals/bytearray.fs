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

    let single input =
        if Seq.length input = 1 then
            Option.Some (Seq.head input)
        else
            Option.None
            
    let withreplace replacement_index replacement input =
        let replacer index current_value =
            if replacement_index = index then replacement
            else current_value
 
        Seq.mapi replacer input        
    let mapz f s = Seq.map (fun x -> (x, f x)) s
    
module Array =
    let withreplace replacement_index replacement input =
        let replacer index current_value =
            if replacement_index = index then replacement
            else current_value
            
        Array.mapi replacer input
        