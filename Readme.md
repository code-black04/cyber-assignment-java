- Command to compile .java files

```
javac *.java
```

- Command to create public and private key for server

```
java RSAKeyGenerator server
```

- Command to create public and private key for client with userId

```
java RSAKeyGenerator <<userId>>
```

- Command to run server at any port

```
java Server <<port>>
```

- Command to run client with port and userId

```
java Client localhost <<port>> <<userId>>
```
