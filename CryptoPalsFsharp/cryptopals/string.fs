namespace cryptopals

open System.Web

module String =
    let lower (value: string) = value.ToLowerInvariant()

    let split (key: string) (x: string) = x.Split(key) |> seq
    let split2 (key: string) (x: string): (string * string) =
        let result = x.Split(key, 2)
        match result with
            | [| a |] -> (a, "")
            | [| a; b |] -> (a, b)
            | _ -> failwith "todo"
            
    let replace (f: string) (t: string) (s: string) = s.Replace(f, t)

    let urlencode (value: string) = HttpUtility.UrlEncode(value)