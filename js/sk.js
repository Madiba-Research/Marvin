var CREATE_SOCKET = "createSocket"
var SSLSOCKETFACTORY = "javax.net.ssl.SSLSocketFactory"

// var msg = '"class":"' + class_name + '","func":"' + CREATE_SOCKET + '","local_addr":"' + s.getLocalSocketAddress().toString() + '",remote_addr":"' + s.getRemoteSocketAddress().toString();

var hookedapi_skt = new Set();
var respite = 0;
setInterval(function () {
    Java.perform(function () {
        if (respite >= 15) {
            return
        } else {
            respite += 1
        }
        const create_sockets = Java.enumerateMethods('*!createSocket')
        create_sockets.forEach(element => {
            element["classes"].forEach(_class => {
                var class_name = _class["name"];
                var i_class = Java.use(class_name);
                i_class.class.getMethods().filter((item) => item.getName() == CREATE_SOCKET && item.getDeclaringClass().getName() === SSLSOCKETFACTORY).forEach(m => {
                    if (false == hookedapi_skt.has(class_name + m)) {
                        hookedapi_skt.add(class_name + m);
                        try{
                            i_class.createSocket.overload('java.net.Socket', 'java.io.InputStream', 'boolean').implementation = function (s, consumed, autoClose) { //java.lang.String
                                var ret = this.createSocket.overload('java.net.Socket', 'java.io.InputStream', 'boolean').call(this,s, consumed, autoClose);
                                // var local_addr = s.getLocalAddress();
                                // var local_port = s.getLocalPort();
                                // var remote_host = s.getInetAddress();
                                // var remote_port = s.getPort();
                                var msg = '"class":"' + class_name + '","func":"' + CREATE_SOCKET + '","local_addr":"' + s.getLocalSocketAddress().toString() + '",remote_addr":"' + s.getRemoteSocketAddress().toString();
                                printStackTraceCreateSocket(msg)
                                console.log("111local_addr=" + s.getLocalSocketAddress().toString() + ",remote_addr=" + s.getRemoteSocketAddress().toString());
                                return ret;
                            }
                        }
                        catch{}
                        try{
                            i_class.createSocket.overload('java.net.Socket', 'java.lang.String', 'int', 'boolean').implementation = function (s, host, port, boolean) { //java.lang.String
                                var ret = this.createSocket.overload('java.net.Socket', 'java.lang.String', 'int', 'boolean').call(this,s, host, port, boolean);
                                // var local_host = s.getLocalPort();
                                // var local_port = s.getLocalAddress();
                                // var remote_host = s.getInetAddress();
                                // var remote_port = s.getPort();
                                var msg = '"class":"' + class_name + '","func":"' + CREATE_SOCKET + '","local_addr":"' + s.getLocalSocketAddress().toString() + '","remote_addr":"' + host + ":" + port.toString();
                                printStackTraceCreateSocket(msg);
                                console.log("2222local_addr=" + s.getLocalSocketAddress().toString() + ",remote_addr=" + host + ":"+port.toString());
                                return ret;
                            }
                        }catch{}
                        try{
                            i_class.createSocket.overload('java.lang.String', 'int').implementation = function (host, port) { //java.lang.String
                                var ret = this.createSocket.overload('java.lang.String', 'int').call(this,host, port);
                                // var local_host = ret.getLocalPort();
                                // var local_port = ret.getLocalAddress();
                                // var remote_host = ret.getInetAddress();
                                // var remote_port = ret.getPort();
                                var msg = '"class":"' + class_name + '","func":"' + CREATE_SOCKET + '","local_addr":"' + ret.getLocalSocketAddress().toString() + '","remote_addr":"' + host + ":" + port.toString();
                                printStackTraceCreateSocket(msg);
                                console.log("333local_addr=" + ret.getLocalSocketAddress().toString() + ",remote_addr=" + + host + ":" + port.toString());
                                return ret;
                            }
                        }catch{}
                        try{
                            i_class.createSocket.overload('java.net.InetAddress', 'int').implementation = function (host, port) { //java.lang.String
                                var ret = this.createSocket.overload('java.net.InetAddress', 'int').call(this,host, port);
                                // var local_host = ret.getLocalPort();
                                // var local_port = ret.getLocalAddress();
                                // var remote_host = ret.getInetAddress();
                                // var remote_port = ret.getPort();
                                var msg = '"class":"' + class_name + '","func":"' + CREATE_SOCKET + '","local_addr":"' + ret.getLocalSocketAddress().toString() + '","remote_addr":"' + host.getHostAddress() + ":" + port.toString();
                                printStackTraceCreateSocket(msg);
                                console.log("444local_addr=" + ret.getLocalSocketAddress().toString() + ",remote_addr=" + ret.getHostAddress() + ":" + port.toString());
                                return ret;
                            }
                        }catch{}
                        try{
                            i_class.createSocket.overload('java.lang.String', 'int', 'java.net.InetAddress', 'int').implementation = function (host, port, client_addr, client_port) { //java.lang.String
                                var ret = this.createSocket.overload('java.lang.String', 'int', 'java.net.InetAddress', 'int').call(this,host, port, client_addr, client_port);
                                // var local_host = ret.getLocalPort();
                                // var local_port = ret.getLocalAddress();
                                // var remote_host = ret.getInetAddress();
                                // var remote_port = ret.getPort();
                                var msg = '"class":"' + class_name + '","func":"' + CREATE_SOCKET + '","local_addr":"' + ret.getLocalSocketAddress().toString() + '","remote_addr":"' +  host + ":" + port.toString();
                                printStackTraceCreateSocket(msg);
                                console.log("555local_addr=" + ret.getLocalSocketAddress().toString() + ",remote_addr=" + host + ":" + port.toString());
                                return ret;
                            }
                        }catch{}
                        try{
                            i_class.createSocket.overload('java.net.InetAddress', 'int', 'java.net.InetAddress', 'int').implementation = function (host, port, client_addr, client_port) { //java.lang.String
                                var ret = this.createSocket.overload('java.net.InetAddress', 'int', 'java.net.InetAddress', 'int').call(this,host, port, client_addr, client_port);
                                // var local_host = ret.getLocalPort();
                                // var local_port = ret.getLocalAddress();
                                // var remote_host = ret.getInetAddress();
                                // var remote_port = ret.getPort();
                                var msg = '"class":"' + class_name + '","func":"' + CREATE_SOCKET + '","local_addr":"' + ret.getLocalSocketAddress().toString() + '",remote_addr":"' +  host.getHostAddress() + ":" + port.toString();
                                printStackTraceCreateSocket(msg);
                                console.log("666local_addr=" + ret.getLocalSocketAddress().toString() + ",remote_addr=" +  host.getHostAddress() + ":" + port.toString());
                                return ret;
                            }
                        }catch{}
                    }
                })
            })
        });

    });
}, 1000);


function printStackTraceCreateSocket(msg, type = "createSocket") {
    var ts = Date.now().toString();
    var stacktrace = btoa(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
    send('{"' + type + '":{' + msg + '","stacktrace":"' + stacktrace + '","ts":"' + ts + '"}}');
}
