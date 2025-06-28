# IKEv2_Code


This is a bare minimum snippet (since this was part of exploration for my company so i had to remove some confidential info)
of the larger basic IKE/IPSec implementation using external packages from
n3iwf. There could be overlap of name of the methods, but they would have different signatures for this specific PoC to work.
Since, this code has not been touched for long time, it might be outdated or not run properly.

Pre-requisites: 
1. Knowledge of Golang: https://go.dev/doc/
2. Knowledge of IKEv2: https://datatracker.ietf.org/doc/html/rfc5996
3. Knowledge of Strongswan: https://docs.strongswan.org/docs/latest/index.html
4. Use of Two linux machines, A and B, both built on ARM architectures.


1. For building the binary, use GOOS=linux, GOARCH=arm64
2. Build the binary using 
    ```
    go build init_conn.go 
    ```
3. Install the binary on a linux machine built on arm64 architecture. (on linux A)
4. On linux B, create a strongswan connection file with following contents: 
    ```
    connections {
        myvpn {
            version = 2
            proposals = aes256-sha1-modp2048

            local_addrs = 192.168.65.3
            remote_addrs = 192.168.65.2

            local {
                id = 192.168.65.3
                auth = psk
            }

            remote {
                id = 192.168.65.2
                auth = psk
            }

            children {
                net-net {
                    local_ts = 192.168.65.3
                    remote_ts = 192.168.65.2
                    esp_proposals = aes256-sha1
                    #dpd_action = restart
                    start_action = start
                    #close_action = none
                    mode = transport
                }
            }
        }
    }

    secrets {
        ike-psk {
            id-1 = 192.168.65.3
            id-2 = 192.168.65.2
            secret = "india"
        }
    }
    ```
5. On linux B, load the conf file using 
    ```
    swanctl --load-all
    ```
6. On linux A, run the binary (might need root user permissions)
    ```
    ./init_conn
    ```
7. Verify the connection is up using xfrm commands 

    a. On linux B 
        ```
        root@jtomar-server:/etc/swanctl/conf.d# ip xfrm policy 
        src 192.168.65.3/32 dst 192.168.65.2/32 
                dir out priority 367231 
                tmpl src 0.0.0.0 dst 0.0.0.0
                        proto esp spi 0x752f8e13 reqid 1 mode transport
        src 192.168.65.2/32 dst 192.168.65.3/32 
                dir in priority 367231 
                tmpl src 0.0.0.0 dst 0.0.0.0
                        proto esp reqid 1 mode transport
        src 0.0.0.0/0 dst 0.0.0.0/0 
                socket in priority 0 
        src 0.0.0.0/0 dst 0.0.0.0/0 
                socket out priority 0 
        src 0.0.0.0/0 dst 0.0.0.0/0 
                socket in priority 0 
        src 0.0.0.0/0 dst 0.0.0.0/0 
                socket out priority 0 
        src ::/0 dst ::/0 
                socket in priority 0 
        src ::/0 dst ::/0 
                socket out priority 0 
        src ::/0 dst ::/0 
                socket in priority 0 
        src ::/0 dst ::/0 
                socket out priority 0 
        root@jtomar-server:/etc/swanctl/conf.d# ip xfrm state
        src 192.168.65.3 dst 192.168.65.2
                proto esp spi 0x752f8e13 reqid 1 mode transport
                replay-window 0 
                auth-trunc hmac(sha1) 0xeec1819d02d6f998a097297de71eb287b5f4e491 96
                enc cbc(aes) 0x6f8d7eb1e1ff0654c6c962dd791de54ba62678599be9b09d29a8fcc98b225e04
                anti-replay context: seq 0x0, oseq 0x0, bitmap 0x00000000
                sel src 192.168.65.3/32 dst 192.168.65.2/32 
        src 192.168.65.2 dst 192.168.65.3
                proto esp spi 0xc1d4888c reqid 1 mode transport
                replay-window 32 
                auth-trunc hmac(sha1) 0xf8e1c2a5acd98ac2c832e1c7444b0b2591dae5fa 96
                enc cbc(aes) 0x7eec0c56ed179b12f173219d2228825904a9af037eaa234da893323994e0f67f
                anti-replay context: seq 0x0, oseq 0x0, bitmap 0x00000000
                sel src 192.168.65.2/32 dst 192.168.65.3/32 
        root@jtomar-server:/etc/swanctl/conf.d# 
        ```
    b. On linux A
        ```
        root@jtomar:/home/jtomar# ip xfrm state
        src 192.168.65.2 dst 192.168.65.3
                proto esp spi 0xcdc888b7 reqid 0 mode transport
                replay-window 0 
                auth-trunc hmac(sha1) 0x1ea98781051e9e86fc65db4dcf47c389c15c7648 96
                enc cbc(aes) 0xbc8f916c6c0044dabe523007c079f75583e6babbe43abed1dffd9e343bef2df5
                anti-replay context: seq 0x0, oseq 0x0, bitmap 0x00000000
                sel src 0.0.0.0/0 dst 0.0.0.0/0 
        src 192.168.65.3 dst 192.168.65.2
                proto esp spi 0xc440fc01 reqid 0 mode transport
                replay-window 0 
                auth-trunc hmac(sha1) 0x954d2076908224ccf382fa306ab2d253da6f3460 96
                enc cbc(aes) 0xce812b34a7ec9e3ee55fc7fd578f9c2d16bf193c094c15f8da1ae5afb6564748
                anti-replay context: seq 0x0, oseq 0x0, bitmap 0x00000000
                sel src 0.0.0.0/0 dst 0.0.0.0/0 
        root@jtomar:/home/jtomar# 
        root@jtomar:/home/jtomar# ip xfrm policy
        src 192.168.65.2/32 dst 192.168.65.3/32 proto icmp 
                dir out priority 0 
                tmpl src 192.168.65.2 dst 192.168.65.3
                        proto esp spi 0xcdc888b7 reqid 0 mode transport
        src 192.168.65.3/32 dst 192.168.65.2/32 proto icmp 
                dir in priority 0 
                tmpl src 192.168.65.3 dst 192.168.65.2
                        proto esp spi 0xc440fc01 reqid 0 mode transport
        root@jtomar:/home/jtomar# 
        ```
