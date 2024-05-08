# Web Server

Android app based on https://github.com/gnarea/minimal-ktor-server-android.git

## Create Certificate Authority

- Create private key: `openssl genrsa -des3 -out privkey.pem 2048` pass phrase: `pass`
- Create certificate: `openssl req -x509 -new -nodes -key privkey.pem -sha256 -days 5000 -out cert.pem`
- Install the Root CA on the device

## Create Certificate

- Create private key: `openssl genrsa -des3 -out privkey.pem 2048` pass phrase: `pass`
- Create the CSR: `openssl req  -new -key privkey.pem -out cert.csr`
- Specify domain names and IP addresses in `cert.ext`
- Create the certificate: `openssl x509 -req -in cert.csr -CA ../root-ca/cert.pem -CAkey ../root-ca/privkey.pem -CAcreateserial -out cert.crt -days 5000 -sha256 -extfile cert.ext`

## Convert from PEM to JKS

- PEM -> PKCS12 `openssl pkcs12 -export -in cert.crt -inkey privkey.pem -out keystore.p12 -name "alias"` pass phrase: `pass`
- PKCS12 -> BKS `keytool -importkeystore -alias "alias" -srckeystore keystore.p12 -srcstoretype PKCS12 -srcstorepass pass -storepass password -deststoretype BKS -providerpath ~/Downloads/bcprov-jdk18on-177.jar -provider org.bouncycastle.jce.provider.BouncyCastleProvider -destkeystore keystore.bks` pass phrase: `password`

## Push file to device's download folder

- `adb push ca/keystore.jks /sdcard/Download`


## Push hooked website to device's folder

- `adb push index.html /sdcard/Download`

**Important:** We cannot make sure that the JS on our website executes before the JS that is injected into a WebView. One example is JS that is injected in the `WebViewClient.onPageStarted` function. The order when injecting JS from this function depends on how fast the JS on the website is executed. Only sometimes the JS on the website executes before the injected JS.d`