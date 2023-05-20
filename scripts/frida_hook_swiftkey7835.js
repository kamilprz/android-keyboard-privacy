Java.perform(function() {
    var array_list = Java.use("java.util.ArrayList");
    var hook = null;
    try {
        hook = Java.use("a36");
        hook.get.implementation = function() {
            console.log('Bypassing a36.get() ');
            return null;
        }
        console.log('Found a36, overiding')
    } catch (err) {
        console.log("a36 not found")
    };
    try {
         hook = Java.use("vn7");
        hook.l.implementation = function() {
            console.log('Bypassing vn7.l() ');
            return true;
       }
        console.log('Found vn7, overiding')
    } catch (err) {
        console.log("vn7 not found")
    };
    try {
         hook = Java.use("my7");
        hook.a.implementation = function(certs, str) {
            console.log('Bypassing my7.a() ');
            return array_list.$new();
       }
        console.log('Found my7, overiding')
    } catch (err) {
        console.log("my7 not found")
    };
    try {
         hook = Java.use("xy7");
        hook.a.implementation = function(certs, str) {
            console.log('Bypassing xy7.a() ');
            return array_list.$new();
       }
        console.log('Found xy7, overiding')
    } catch (err) {
        console.log("xy7 not found")
    };

    // disable X509 checks
    try {
         var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
         var SSLContext = Java.use('javax.net.ssl.SSLContext');
         // TrustManager (Android < 7)
         var TrustManager = Java.registerClass({
                 // Implement a custom TrustManager
                 name: 'dev.asd.test.TrustManager',
                 implements: [X509TrustManager],
                 methods: {
                         checkClientTrusted: function (chain, authType) {console.log('Bypassing Trustmanager checkClientTrusted'+pid);},
                         checkServerTrusted: function (chain, authType) {console.log('Bypassing Trustmanager checkServerTrusted'+pid);},
                         getAcceptedIssuers: function () {return []; }
                 }
         });
         // Prepare the TrustManager array to pass to SSLContext.init()
         var TrustManagers = [TrustManager.$new()];
         // Get a handle on the init() on the SSLContext class
         console.log('x509 overloads '+SSLContext.init.overloads.length);
         var SSLContext_init = SSLContext.init.overload(
                 '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
         // Override the init method, specifying the custom TrustManager
         SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
                 console.log('Bypassing Trustmanager request'+pid);
                 SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
         };
         console.log('Found javax.net.ssl.X509TrustManager, overiding')
     } catch (err) {
         console.log("javax.net.ssl.X509TrustManager not found")
     };
 
});