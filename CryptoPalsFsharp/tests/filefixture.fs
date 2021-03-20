module Filefixture

open System.IO
open NUnit.Framework
open FsUnit

[<Test>]
let ReadIOStream () =
    use s = new MemoryStream()
    use w = new StreamWriter(s)
    w.Write("abcd\nefgh\nijkl")
    w.Flush()
    s.Position <- (int64)0
    
    File.getAllLines s |> should equal ["abcd"; "efgh"; "ijkl"]

[<Test>]
let ReadFromResource () =
    File.readTestData "readfile.txt" |> should equal ["abcd"; "efgh"; "ijkl"]
