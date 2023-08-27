module Random

open System
open System.Numerics
open cryptopals

let randomInt min max = int (System.Random.Shared.NextInt64((int64) min, (int64) max))
let randomUintFullRange = uint32 (Random.Shared.NextInt64(0, int64 UInt32.MaxValue))
let randomBytes size =
    let array = Array.create size (byte 0)
    System.Random.Shared.NextBytes array
    array |> Seq.map int

let randomBigInt bits = randomBytes (bits / 8 + 1) |> Seq.toBigintBe

    
let choose sequence =
    Seq.item (randomInt 0 (Seq.length sequence)) sequence

let generate_state n w f (seed: uint32) =
    let scanner prev i = (f * (prev ^^^ (prev >>> (w-2)))) + i
    
    seq { 1u .. 1u .. uint(n-1) } |> Seq.scan scanner seed |> Seq.toArray

type mtInit =
    | Seed of uint
    | State of uint array * int

let mt19937 (init: mtInit) =
    let (w, n, m, r) = (32, 624, 397, 31)
    let a = 0x9908B0DFu
    let (u, d) = (11, 0xFFFFFFFFu)
    let (s, b) = (7, 0x9D2C5680u)
    let (t, c) = (15, 0xEFC60000u)
    let l = 18
    let f = 1812433253u
    
    let lower_mask = (1u <<< r) - 1u
    let upper_mask = ~~~ lower_mask
    
    let twist (state: uint array, _) =
        let twist_one i =
            let x = (state[i] &&& upper_mask) ||| (state[(i+1) % n] &&& lower_mask)
            let xFactor = if (x % 2u = 0u) then 0u else a
            let xA = (x >>> 1) ^^^ xFactor
            state[(i + m) % n] ^^^ xA

        (seq { 0 .. 1 .. (n-1) } |> Seq.map twist_one |> Seq.toArray, 0) 
    
    let maybetwist (state: uint array, index: int) =
        if index = n then
            twist (state, index)
        else
            (state, index)
    
    let mt1 y = y ^^^ ((y >>> u) &&& d)
    let mt2 y = y ^^^ ((y <<< s) &&& b)
    let mt3 y = y ^^^ ((y <<< t) &&& c)
    let mt4 y = y ^^^ (y >>> l)
    
    let mt = mt1 >> mt2 >> mt3 >> mt4       
    
    let next (state: uint array, index: int) =
        Some (mt state[index], maybetwist (state, index + 1))
    
    let initial_state = maybetwist (
        match init with
        | Seed seed -> (generate_state n w f seed, n)
        | State (s, i) -> (s, i)
    )
    
    Seq.unfold next initial_state
