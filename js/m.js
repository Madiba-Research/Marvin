var hookedapi = new Set();
var respite = 0;
setInterval(function () {
    Java.perform(function () {
        if (respite >= 30){
            return
        }else{
            respite+=1
        }
        const groups = Java.enumerateMethods('*!verify')
        groups.forEach(element => {
            element["classes"].forEach(_class => {
                try {
                    var class_name = _class["name"];
                    var i_class = Java.use(class_name);
                    i_class.class.getMethods().filter((item) => item.getName() == "verify").forEach(m => {
                        m.getDeclaringClass().getInterfaces().filter((item) => ["javax.net.ssl.HostnameVerifier", "com.android.org.conscrypt.ConscryptHostnameVerifier"].includes(item.getName())).forEach(ii => {
                            
                            var func = "verify"
                            if (false === hookedapi.has(class_name + func)){
                                if (ii.getName() == "javax.net.ssl.HostnameVerifier") {
                                    i_class.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (hostname, session) {
                                        hookedapi.add(class_name + func);
                                        console.log(class_name + "->" + hostname);
                                        var certs = session.getPeerCertificates();
                                        var cert = Java.cast(certs[0], Java.use('java.security.cert.X509Certificate'));
                                        var subjectDN = cert.getSubjectDN().toString().replaceAll(/"/g, '');
                                        var issueDN = cert.getIssuerDN().toString().replaceAll(/"/g, '');
                                        var expire = cert.getNotAfter();
                                        var msg = '"class":"' + class_name + '","hostname":"' + hostname + '","subjectDN":"' + subjectDN+ '","issueDN":"' + issueDN + '","expire":"' + expire;
                                        printStackTraceVerify(msg);

                                        return this.verify(hostname, session);
                                    }
                                } else if (ii.getName() == "com.android.org.conscrypt.ConscryptHostnameVerifier") {
                                    i_class.verify.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (certs, hostname, session) {
                                        hookedapi.add(class_name + func);
                                        console.log(method.class + "->" +hostname+",result=" +this.verify(certs, hostname, session));
                                        var cert = Java.cast(certs[0], Java.use('java.security.cert.X509Certificate'));
                                        var subjectDN = cert.getSubjectDN().toString().replaceAll(/"/g, '');
                                        var issueDN = cert.getIssuerDN().toString().replaceAll(/"/g, '');
                                        var expire = cert.getNotAfter();
                                        var msg = '"class":"' + class_name + '","hostname":"' + hostname + '","subjectDN":"' + subjectDN+ '","issueDN":"' + issueDN + '","expire":"' + expire;
                                        printStackTraceVerify(msg);
                                        return this.verify(certs, hostname, session);
                                    }

                                }
                            }
                        })

                    })
                } catch { }
            });
        });

    });

}, 1000);


function printStackTraceVerify(msg, type = "verify") {
    var ts = Date.now().toString();
    var stacktrace = btoa(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
    send('{"' + type + '":{' + msg + '","stacktrace":"' + stacktrace +'","ts":"' + ts +'"}}');
}
