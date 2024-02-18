- Command to compile
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

- Command to run server
```
java Server 8082
```

- Command to run client with userId
```
java Client localhost 8082 <<userId>>
```
