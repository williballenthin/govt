# Breaking API changes from version 1.0

1. Initialization
-----------------
Previously, initializing the client required creating the client with the relevant API key and other parameters:
```
   // Create the client
   c := govt.Client{Apikey: "api key"}
```

Now, the initialization is done via the New function with which checks that the client is initialized correctly:
```
  // Create the client
  c := govt.New(govt.SetErrorLog(log.New(os.Stderr, "VT: ", log.Lshortfile), govt.SetApikey(apikey), govt.SetUrl(apiurl))
```

You can provide multiple initialization functions of type govt.OptionFunc to help with the initialization.

| *Function*    | *Description*                                  | *Mandatory* |
|---------------|------------------------------------------------|-------------|
| SetApikey     | Provide the API key to use                     | true        |
| SetHttpClient | Provide a custom HTTP client                   | false       |
| SetUrl        | Provide a different URL from the default one   | false       |
| SetBasicAuth  | Provide proxy credentials                      | false       |
| SetErrorLog   | Set error logger to write errors to            | false       |
| SetTraceLog   | Set trace logger to dump requests / replies to | false       |

2. Client implementation details
--------------------------------
Client implementation details such as internal fields are now private. This move was made so it will be easier to evolve and change the API without breaking compatibility with existing code.

3. File uploads
---------------
To improve memory footprint requirements, file uploads are now streaming using a goroutine.
