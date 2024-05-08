- create keystore (in Android Studio)
- password: password, alias: alias
- saved in `certificate/provider-keystore.jks`
- export the certificate `keytool -export -rfc -keystore provider-keystore.jks -alias alias -file out.pem `


https://xdaforums.com/t/best-way-to-update-webview-on-custom-rom.4479333/

Original APK MD5

- `adb pull /system/framework/framework-res.apk`
- `md5 framework-res.apk --> MD5 (framework-res.apk) = 2b459fd5e8ec9b420acd1e3193a69c08`
- `cp framework-res.apk original-framework-res.apk`
- `md5 original-framework-res.apk --> MD5 (original-framework-res.apk) = 2b459fd5e8ec9b420acd1e3193a69c08`

- `apktool if framework-res.apk`
- `apktool d framework-res.apk`
- open `framework-res/res/xml/config_webview_packages.xml`
- insert 
  - ```
  <webviewprovider description="WV Injection Custom Provider" packageName="com.beerphilipp.wvinjection.provider">
        <signature>MIICjjCCAXYCAQEwDQYJKoZIhvcNAQELBQAwDTELMAkGA1UEBhMCQVQwHhcNMjQwMzE5MTQyNjMzWhcNNDkwMzEzMTQyNjMzWjANMQswCQYDVQQGEwJBVDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKjPfLcKuP2IOgffiXHBcij7LjbFuSCsANO2IxUsgG9wTECg6OrEio/WrPL/HEJArkkR04X74I4Z6uOd6gguYsi6+t7PMI1VhsjfRiGMV3HNFGkemIvUg6pxNa4GdCZ9k9vGAUUutNyaX4f6u6wjj2uN+VPPTM4eK+lQQqvMFJs5ZWtIK/dKi6pZShPR610oRjERD5OVka7R2n1GBPi7/rBXiVtOxtgyz5BnA7D4o+vcV1sj4KvKaVrjvovLXoRZaz26Dbytn+EWkRhlS06e1hErDFUIo2dK2yZunmAue3zPNzrbzo+yVS6q3nJxpLj2iiT9b3jBgF598bs+T4ytNpsCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEALb37MLKzRlNvmy8Q0Dp0GKOCYDUAzGdcpdQMwAFmAlX92fDwZZEN5zJKokf6D77ejDbWs/JkHLqoI4s0eKNFOeeEmjqU51zy/tl2vAgAb0qfsAOxfltAht1erl0cA/WfL633876r4JDkDrQjOvmbELkCzHL+7PkR6okVf8nz0e6gLzVU7PAG+tph/dwTLga2m/h3qSUUh6DqfUYgacX7cH6GVYH77qTHitsIhGReeeNOFc1+kyvAOpHS9UHpklprQEz5gAYzNJ8CHef0QuXtM62OIAQvpCcJ+b70NFmwFOh829GosUbAvU7qOCaf/ddhgY5ASppYgalZLjkhVSAd4Q==</signature>
    </webviewprovider>
  ```
- rebuild the apk: `apktool b framework-res --use-aapt2`

- `cd framework-res/build/apk`
- `zip -r ../../../framework-res_EDITED.apk *`
  

- `mkdir res`
- `mkdir res/xml`
- `cp framework-res/build/apk/res/xml/config_webview_packages.xml res/xml/config_webview_packages.xml`
- `zip -u framework-res.apk res/xml/config_webview_packages.xml`


## Install Custom Recovery