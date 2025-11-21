# dcn-fortios-go-client

A Go client library for managing FortiOS firewall resources via the FortiGate
REST API.

## Features

- Manage IPv4 addresses
- Manage IPv6 addresses
- Manage address groups

## Installation

```bash
go get github.com/NorskHelsenett/dcn-fortios-go-client
```

## Usage

```go
package main

import (
    "github.com/NorskHelsenett/dcn-fortios-go-client/pkg/client"
    "github.com/NorskHelsenett/dcn-fortios-go-client/pkg/types/fortiostypes"
)

func main() {
    // Create a new FortiGate client
    client := forticlient.NewFortiClient(
        "https://fortigate.example.com",
        "root",  // VDOM
        "your-api-token",
    )

    // Create an IPv4 address
    address := fortiostypes.FortigateIPv4Address{
        Name:    "MyServer",
        Subnet:  "192.168.1.10 255.255.255.255",
        Type:    "ipmask",
        Comment: "Application server",
    }
    
    err := client.CreateIPv4Address(address)
    if err != nil {
        panic(err)
    }
}
```

## License

See LICENSE file for details.
