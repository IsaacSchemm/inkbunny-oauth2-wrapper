# inkbunny-oauth2-wrapper

This is a (non-standards-compliant) OAuth2 server that prompts a user for an
Inkbunny username and password, and returns the Inkbunny SID and user ID. The
server runs on Azure Functions and is completely stateless.

You can deploy it to your own Azure account if you'd like. Just set a client
ID and client secret for OAuth by adding an application setting in the
Configuration section, with `ClientSecret_{id}` as the name and `{secret}`
as the value. `{id}` should be an integer, and `{secret}` should be a random
256-bit key, encoded in base 64. For example:

    "ClientSecret_100": "ZJY677q34+PWuW4myNmSCblfVHhTPwFqx6xZNLWqyQs="

To create a random base-64-encoded 256-bit key in Visual Studio, you can enter
this into F# Interactive:

    let r = new System.Random() in [0 .. 31] |> Seq.map (fun _ -> r.Next(0, 255) |> byte) |> Array.ofSeq |> System.Convert.ToBase64String;;

