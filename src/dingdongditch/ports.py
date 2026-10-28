"""Port lists and default service names for the built-in scanner."""

from __future__ import annotations

# Default service name per port, used when we can't fingerprint anything better.
SERVICE_NAMES: dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    69: "tftp", 79: "finger", 80: "http", 81: "http", 88: "kerberos", 110: "pop3",
    111: "rpcbind", 113: "ident", 119: "nntp", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 179: "bgp", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 512: "exec", 513: "login", 514: "shell", 515: "printer", 548: "afp",
    554: "rtsp", 587: "submission", 631: "ipp", 636: "ldaps", 873: "rsync", 990: "ftps",
    993: "imaps", 995: "pop3s", 1080: "socks", 1099: "rmiregistry", 1433: "ms-sql-s",
    1521: "oracle", 1524: "ingreslock", 1723: "pptp", 1883: "mqtt", 2049: "nfs",
    2121: "ftp", 2181: "zookeeper", 2375: "docker", 2376: "docker-tls", 3000: "http",
    3128: "squid-http", 3268: "ldap-gc", 3306: "mysql", 3389: "ms-wbt-server",
    3632: "distccd", 4369: "epmd", 5000: "http", 5060: "sip", 5432: "postgresql",
    5601: "kibana", 5672: "amqp", 5900: "vnc", 5901: "vnc", 5984: "couchdb",
    6000: "x11", 6379: "redis", 6443: "kubernetes", 6667: "irc", 7001: "weblogic",
    8000: "http", 8008: "http", 8009: "ajp13", 8080: "http-proxy", 8081: "http",
    8180: "http", 8443: "https-alt", 8888: "http", 9000: "http", 9090: "http",
    9092: "kafka", 9100: "jetdirect", 9200: "elasticsearch", 9418: "git",
    11211: "memcached", 27017: "mongodb", 50000: "http",
    # Web apps, admin panels and middleware that show up in Vulhub-style labs.
    2222: "ssh-alt", 2379: "etcd", 3690: "svn", 4848: "glassfish", 5005: "jdwp",
    5985: "wsman", 5986: "wsmans", 7474: "neo4j", 8086: "influxdb", 8088: "http",
    8090: "http", 8161: "activemq-web", 8500: "consul", 8983: "solr", 9001: "http",
    9443: "https-alt", 9990: "jboss-mgmt", 10000: "webmin", 15672: "rabbitmq-mgmt",
    50070: "hadoop-namenode", 61616: "activemq",
}

# Usually UDP, so a TCP connect scan normally won't see them. Kept for the
# rare TCP listener and for a future UDP scan.
MOSTLY_UDP: set[int] = {69, 161, 5060}

# A hand-picked "most interesting" set: common services plus the risky ones
# attackers look for (databases, remote admin, legacy cleartext protocols).
TOP_PORTS: list[int] = sorted(SERVICE_NAMES)

# Ports where the service is usually TLS from the first byte.
TLS_PORTS: set[int] = {443, 465, 636, 990, 993, 995, 2376, 5986, 6443, 8443, 9443}

PROFILES: dict[str, list[int]] = {
    "quick": TOP_PORTS,
    "default": sorted(set(range(1, 1025)) | set(TOP_PORTS)),
    "full": list(range(1, 65536)),
}


def parse_ports(spec: str) -> list[int]:
    """Parse '22,80,8000-8100' into a sorted list of ports."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad or not ports:
        raise ValueError(f"Invalid port specification: {spec!r}")
    return sorted(ports)
