"""
This addon allows conditional TLS Interception based on a user-defined strategy.
Example:
    > mitmdump -s tls_passthrough.py
    1. curl --proxy http://localhost:8080 https://example.com --insecure
    // works - we'll also see the contents in mitmproxy
    2. curl --proxy http://localhost:8080 https://example.com
    // fails with a certificate error, which we will also see in mitmproxy
    3. curl --proxy http://localhost:8080 https://example.com
    // works again, but mitmproxy does not intercept and we do *not* see the contents
"""
import collections
import random
import os
import time

from abc import ABC, abstractmethod
from enum import Enum

from mitmproxy import connection, ctx, tls
from mitmproxy.utils import human

# cgi.connect.qq.com --> 43.154.252.110:443


# CERT_TYPE = os.environ['CERT_TYPE']
TLS_PASSTHROUGH_LOG = os.environ["PASSTHROUGH_LOG"]
print(TLS_PASSTHROUGH_LOG)

class InterceptionResult(Enum):
    SUCCESS = 1
    FAILURE = 2
    SKIPPED = 3


class TlsStrategy(ABC):
    def __init__(self):
        # A server_address -> interception results mapping
        self.history = collections.defaultdict(lambda: collections.deque())

    @abstractmethod
    def should_intercept(self, server_address: connection.Address,sni) -> bool:
        raise NotImplementedError()

    def record_success(self, server_address,sni):
        self.history[(server_address,sni)].append(InterceptionResult.SUCCESS)

    def record_failure(self, server_address,sni):
        self.history[(server_address,sni)].append(InterceptionResult.FAILURE)

    def record_skipped(self, server_address,sni):
        self.history[(server_address,sni)].append(InterceptionResult.SKIPPED)

    def record_size():
        return self.history.len()


class ConservativeStrategy(TlsStrategy):
    """
    Conservative Interception Strategy - only intercept if there haven't been any failed attempts
    in the history.
    """

    def __init__(self):
        super().__init__()
        self.addr_whitelist = set()
        self.sni_whitelist = set()

    def should_intercept(self, server_address: connection.Address,sni) -> bool:
        return InterceptionResult.FAILURE not in self.history[(server_address, sni)]
    
class ProbabilisticStrategy(TlsStrategy):
    """
    Fixed probability that we intercept a given connection.
    """
    def __init__(self, p: float):
        self.p = p
        super().__init__()

    def should_intercept(self, server_address: connection.Address,sni) -> bool:
        return random.uniform(0, 1) < self.p


class MaybeTls:
    strategy: TlsStrategy

    def load(self, l):
        self.strategy = ConservativeStrategy()
        l.add_option(
            "tls_strategy", int, 0,
            "TLS passthrough strategy. If set to 0, connections will be passed through after the first unsuccessful "
            "handshake. If set to 0 < p <= 100, connections with be passed through with probability p.",
        )

    def configure(self, updated):
        if "tls_strategy" not in updated:
            return
        if ctx.options.tls_strategy > 0:
            self.strategy = ProbabilisticStrategy(ctx.options.tls_strategy / 100)
        else:
            self.strategy = ConservativeStrategy()

    def tls_clienthello(self, data: tls.ClientHelloData):
        sni = data.client_hello.sni
        server_address = data.context.server.peername
        if not self.strategy.should_intercept(server_address,sni):
            ctx.log(f"TLS passthrough: {human.format_address(server_address)} -> {sni}.")
            data.ignore_connection = True
            self.strategy.record_skipped(server_address,sni)
            self.write_log(f"TLS Passthrough: {human.format_address(server_address)} -> {sni}")

    def tls_established_client(self, data: tls.TlsData):
        sni = data.conn.sni
        server_address = data.context.server.peername
        ctx.log(f"TLS handshake successful: {human.format_address(server_address)} -> {sni}")
        self.strategy.record_success(server_address,sni)
        self.write_log(f"TLS Success: {human.format_address(server_address)} -> {sni}")

    def tls_failed_client(self, data: tls.TlsData):
        sni = data.conn.sni
        server_address = data.context.server.peername
        ctx.log(f"TLS handshake failed: {human.format_address(server_address)} -> {sni}")
        self.strategy.record_failure(server_address,sni)
        self.write_log(f"TLS Failure: {human.format_address(server_address)} -> {sni}")

    
    def write_log(self, log):
        with open(TLS_PASSTHROUGH_LOG, "a") as f:
            ts_log = log + f", {time.time()}\n"
            f.write(ts_log)


addons = [MaybeTls()]
