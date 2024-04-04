var hooked_apis = new Set();
var repeat = 0;
var CHECK_CLIENT_TRUSTED = "checkClientTrusted"
var CHECK_SERVER_TRUSTED = "checkServerTrusted";
var GET_ACCEPTED_ISSUER = "getAcceptedIssuer";

var CHECK_VALIDITY = "checkValidity";
var NOT_AFTER = "getNotAfter";
var NOT_BEFORE = "getNotBefore";

var SET_DEFAULT_SSLSOCKET_FACTORY = "setDefaultSSLSocketFactory"
var SET_DEFAULT_HOSTNAME_VERIFIER = "setDefaultHostnameVerifier"

 // X509TrustManager
var X509_TRUST_MANAGER = "javax.net.ssl.X509TrustManager"
var X509_EXTENDED_TRUST_MANAGER = "javax.net.ssl.X509ExtendedTrustManager"

setInterval(function () {
    Java.perform(function () {
        // if (repeat >= 20){
        //     return
        // }else{
        //     repeat+=1
        // }

        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultSSLSocketFactory.overload("javax.net.ssl.SSLSocketFactory").implementation = function(socketFactory) {
            console.log("pid="+ Process.id+", HttpsURLConnection.setDefaultSSLSocketFactory is called!");
            var class_name = "javax.net.ssl.SSLSocketFactory";
            var msg = '"pid":"'+Process.id +'","class":"' + class_name + '","func":"' + SET_DEFAULT_SSLSOCKET_FACTORY;
            printStackTraceCheck(msg);
            HttpsURLConnection.setDefaultSSLSocketFactory.overload("javax.net.ssl.SSLSocketFactory").call(this, socketFactory);
        }

        HttpsURLConnection.setDefaultHostnameVerifier.overload("javax.net.ssl.HostnameVerifier").implementation = function(hostnameVerifier) {
            console.log("pid="+ Process.id+", HttpsURLConnection.setDefaultHostnameVerifier is called!");
            var class_name = "javax.net.ssl.HostnameVerifier";
            var msg = '"pid":"'+Process.id +'","class":"' + class_name + '","func":"' + SET_DEFAULT_HOSTNAME_VERIFIER;
            printStackTraceCheck(msg);
            HttpsURLConnection.setDefaultHostnameVerifier.overload("javax.net.ssl.HostnameVerifier").call(this, hostnameVerifier);
        }

        var methods = [CHECK_SERVER_TRUSTED, GET_ACCEPTED_ISSUER, CHECK_CLIENT_TRUSTED];
        // *!*certificate*
        methods.forEach(m => {
            var mm = '*!' + m
            const groups = Java.enumerateMethods(mm);
            groups.forEach(element => {
                element["classes"].forEach(_class => {
                    try {
                        var class_name = _class["name"];
                        var IClass = Java.use(class_name);
                       
                        IClass.class.getInterfaces().filter(item => [X509_TRUST_MANAGER, X509_EXTENDED_TRUST_MANAGER].includes(item.getName())).forEach(ii => {
                            if (false == hooked_apis.has(class_name + m)) {
                                IClass.getAcceptedIssuers.overload().implementation = function() {
                                    // console.log(class_name + "." + GET_ACCEPTED_ISSUER);
                                    hooked_apis.add(class_name + m);
                                    var msg = "pid=" + Process.id + ", "+class_name + '","func":"' + GET_ACCEPTED_ISSUER;
                                    printStackTraceCheck(msg);
                                    return IClass.getAcceptedIssuers.overload().call(this);
                                }

                                if (X509_TRUST_MANAGER === ii.getName()) {
                                    IClass.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').implementation = function(certs, str) {
                                        hooked_apis.add(class_name + m);
                                        var subjectDN = certs[0].getSubjectDN().toString().replaceAll(/"/g, '');
                                        var issueDN = certs[0].getIssuerDN().toString().replaceAll(/"/g, '');
                                        var expire = certs[0].getNotAfter();
                                        // console.log(IClass +"..." + class_name +"====>" + IClass.class.getInterfaces());
                                        // console.log(class_name + "." + CHECK_SERVER_TRUSTED+", subjectDN=" + subjectDN + "; IssuerDN=" +issueDN+ "; expire=" + expire);
                                        console.log("pid=" + Process.id + ", "+class_name + "." + CHECK_SERVER_TRUSTED+", subjectDN=" + subjectDN + "; IssuerDN=" +issueDN+ "; expire=" + expire);
                                        var msg = '"pid":"'+Process.id +'","class":"' + class_name + '","func":"' + CHECK_SERVER_TRUSTED + '","subjectDN":"' + subjectDN+ '","issueDN":"' + issueDN + '","expire":"' + expire;
                                        printStackTraceCheck(msg);
                                        IClass.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').call(this, certs, str);
                                    }

                                    IClass.checkClientTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').implementation = function(certs, str) {
                                        hooked_apis.add(class_name + m);
                                        var subjectDN = certs[0].getSubjectDN().toString().replaceAll(/"/g, '');
                                        var issueDN = certs[0].getIssuerDN().toString().replaceAll(/"/g, '');
                                        var expire = certs[0].getNotAfter();
                                        // console.log(IClass +"..." + class_name +"====>" + IClass.class.getInterfaces());
                                        // console.log(class_name + "." + CHECK_CLIENT_TRUSTED+", subjectDN=" + subjectDN + "; IssuerDN=" +issueDN+ "; expire=" + expire);
                                        console.log("pid=" + Process.id + ", "+class_name + "." + CHECK_CLIENT_TRUSTED+", subjectDN=" + subjectDN + "; IssuerDN=" +issueDN+ "; expire=" + expire);
                                        var msg = '"pid":"'+Process.id +'","class":"' + class_name + '","func":"' + CHECK_CLIENT_TRUSTED + '","subjectDN":"' + subjectDN+ '","issueDN":"' + issueDN + '","expire":"' + expire;
                                        printStackTraceCheck(msg);
                                        IClass.checkClientTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').call(this, certs, str);
                                    }
                                }
                                else if (X509_EXTENDED_TRUST_MANAGER === ii.getName()) {
                                    IClass.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.net.Socket').implementation = function(certs, authType, socket) {
                                        hooked_apis.add(class_name + m);
                                        var subjectDN = certs[0].getSubjectDN().toString().replaceAll(/"/g, '');
                                        var issueDN = certs[0].getIssuerDN().toString().replaceAll(/"/g, '');
                                        var expire = certs[0].getNotAfter();
                                        console.log("pid=" + Process.id + ", "+class_name + "." + CHECK_SERVER_TRUSTED+", subjectDN=" + subjectDN + "; IssuerDN=" +issueDN+ "; expire=" + expire);
                                        var msg = '"pid":"'+Process.id +'","class":"' + class_name + '","func":"' + CHECK_SERVER_TRUSTED + '","subjectDN":"' + subjectDN+ '","issueDN":"' + issueDN + '","expire":"' + expire;
                                        printStackTraceCheck(msg);
                                        IClass.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.net.Socket').call(this, certs, authType, socket);
                                    }

                                    IClass.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'javax.net.ssl.SSLEngine').implementation = function(certs, authType, engine) {
                                        hooked_apis.add(class_name + m);
                                        var subjectDN = certs[0].getSubjectDN().toString().replaceAll(/"/g, '');
                                        var issueDN = certs[0].getIssuerDN().toString().replaceAll(/"/g, '');
                                        var expire = certs[0].getNotAfter();
                                        console.log("pid=" + Process.id + ", "+class_name + "." + CHECK_CLIENT_TRUSTED+", subjectDN=" + subjectDN + "; IssuerDN=" +issueDN+ "; expire=" + expire);
                                        var msg = '"pid":"'+Process.id +'","class":"' + class_name + '","func":"' + CHECK_CLIENT_TRUSTED + '","subjectDN":"' + subjectDN+ '","issueDN":"' + issueDN + '","expire":"' + expire;
                                        printStackTraceCheck(msg);
                                        IClass.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'javax.net.ssl.SSLEngine').call(this, authType, engine);
                                    }


                                    IClass.checkClientTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.net.Socket').implementation = function(certs, authType, socket) {
                                        hooked_apis.add(class_name + m);
                                        var subjectDN = certs[0].getSubjectDN().toString().replaceAll(/"/g, '');
                                        var issueDN = certs[0].getIssuerDN().toString().replaceAll(/"/g, '');
                                        var expire = certs[0].getNotAfter();
                                        console.log("pid=" + Process.id + ", "+class_name + "." + CHECK_CLIENT_TRUSTED+", subjectDN=" + subjectDN + "; IssuerDN=" +issueDN+ "; expire=" + expire);
                                        var msg = '"pid":"'+Process.id +'","class":"' + class_name + '","func":"' + CHECK_CLIENT_TRUSTED + '","subjectDN":"' + subjectDN+ '","issueDN":"' + issueDN + '","expire":"' + expire;
                                        printStackTraceCheck(msg);
                                        IClass.checkClientTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.net.Socket').call(this, certs, authType, socket);
                                    }

                                    IClass.checkClientTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'javax.net.ssl.SSLEngine').implementation = function(certs, authType, engine) {
                                        hooked_apis.add(class_name + m);
                                        var subjectDN = certs[0].getSubjectDN().toString().replaceAll(/"/g, '');
                                        var issueDN = certs[0].getIssuerDN().toString().replaceAll(/"/g, '');
                                        var expire = certs[0].getNotAfter();
                                        console.log("pid=" + Process.id + ", "+class_name + "." + CHECK_CLIENT_TRUSTED+", subjectDN=" + subjectDN + "; IssuerDN=" +issueDN+ "; expire=" + expire);
                                        var msg = '"pid":"'+Process.id +'","class":"' + class_name + '","func":"' + CHECK_CLIENT_TRUSTED + '","subjectDN":"' + subjectDN+ '","issueDN":"' + issueDN + '","expire":"' + expire;
                                        printStackTraceCheck(msg);
                                        IClass.checkClientTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'javax.net.ssl.SSLEngine').call(this, authType, engine);
                                    }
                                }
                            }
                        });
                    } catch {
                    }
                });
            });
        });

        var expiry_methods = [CHECK_VALIDITY, NOT_AFTER, NOT_BEFORE]; 
        expiry_methods.forEach(m => {
            var mm = '*!*' + m + '*'
            const groups = Java.enumerateMethods(mm);
            groups.forEach(element => {
                 element["classes"].forEach(_class => {
                    try {
                        var class_name = _class["name"];
                        var IClass = Java.use(class_name);

                        IClass.class.getInterfaces().filter(item => [X509_TRUST_MANAGER].includes(item.getName())).forEach(ii => {
                            if (false == hooked_apis.has(class_name + m)) {
                                IClass.checkValidity.override().implementation = function() {
                                    hooked_apis.add(class_name + m);
                                    console.log(class_name + "." + CHECK_VALIDITY);
                                    var msg = '"pid":"'+Process.id +'","class":"' + class_name + '","func":"' + CHECK_VALIDITY;
                                    printStackTraceCheck(msg);
                                    IClass.checkValidity.override().call(this);
                                }

                                IClass.getNotAfter.override().implementation = function() {
                                    hooked_apis.add(class_name + m);
                                    console.log(class_name + "." + NOT_AFTER);
                                    var msg = '"pid":"'+Process.id +'","class":"' + class_name + '","func":"' + NOT_AFTER;
                                    printStackTraceCheck(msg);
                                    IClass.getNotAfter.override().call(this);
                                }

                                IClass.getNotBefore.override().implementation = function() {
                                    hooked_apis.add(class_name + m);
                                    console.log(class_name + "." + NOT_BEFORE);
                                    var msg = '"pid":"'+Process.id +'","class":"' + class_name + '","func":"' + NOT_BEFORE;
                                    printStackTraceCheck(msg);
                                    IClass.getNotBefore.override().call(this);
                                }
                            }
                        });
                    } catch {
                    }
                });
            });
        });
    });
}, 1000);


function printStackTraceCheck(msg, type = "check") {
    var ts = Date.now().toString();
    var stacktrace = btoa(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
    send('{"' + type + '":{' + msg + '","stacktrace":"' + stacktrace + '","ts":"' + ts +'"}}');
}
