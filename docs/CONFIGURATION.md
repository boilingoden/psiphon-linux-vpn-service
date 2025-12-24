# Configuration

## Quick Start (Copy-Paste Ready)

Pick your use case:

### For Home Network (Recommended)
```json
{
    "LocalHttpProxyPort": 8081,
    "LocalSocksProxyPort": 1081,
    "EgressRegion": "",
    "PropagationChannelId": "FFFFFFFFFFFFFFFF",
    "RemoteServerListDownloadFilename": "remote_server_list",
    "RemoteServerListSignaturePublicKey": "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM=",
    "RemoteServerListUrl": "https://s3.amazonaws.com/psiphon/web/mjr4-p23r-puwl/server_list_compressed",
    "SponsorId": "FFFFFFFFFFFFFFFF",
    "UseIndistinguishableTLS": true,
    "EstablishTunnelTimeoutSeconds": 300,
    "TunnelPoolSize": 1
}
```

### For Mobile/Unstable
Replace the above with `"EstablishTunnelTimeoutSeconds": 600` (10 minutes instead of 5)

### For High Speed
Add `"TunnelPoolSize": 2` and change `"EstablishTunnelTimeoutSeconds": 60`

### For Censorship
Keep defaults but ensure `"UseIndistinguishableTLS": true`

### For Maximum Privacy
Everything above + add at end: `"UpstreamProxyURL": ""`

## How to Apply

```bash
# Edit config
sudo nano /opt/psiphon-tun/psiphon/psiphon.config

# Paste your chosen config

# Save: Ctrl+X, Y, Enter

# Validate JSON
jq . /opt/psiphon-tun/psiphon/psiphon.config

# Apply
sudo systemctl reload psiphon-tun
```

## Parameters Explained

| Parameter | What It Does | Common Values |
|-----------|-------------|----------------|
| `LocalHttpProxyPort` | HTTP proxy port | 8081 (default) |
| `LocalSocksProxyPort` | SOCKS5 proxy port | 1081 (default) |
| `EgressRegion` | VPN exit country | "" (auto), "US", "CA", "GB", "AU" |
| `EstablishTunnelTimeoutSeconds` | Wait time for tunnel | 60 (fast), 300 (normal), 600 (slow) |
| `TunnelPoolSize` | Number of tunnels | 1 (stable), 2-4 (faster) |
| `UseIndistinguishableTLS` | Obfuscation | true (secure), false (faster) |

## Optimization

**For Stability:** `"EstablishTunnelTimeoutSeconds": 600, "TunnelPoolSize": 1`

**For Speed:** `"EstablishTunnelTimeoutSeconds": 60, "TunnelPoolSize": 2`

**For Censorship:** Keep `"UseIndistinguishableTLS": true`

## Troubleshooting Config

```bash
# JSON syntax error?
jq . /opt/psiphon-tun/psiphon/psiphon.config
# If error, restore backup:
sudo cp ~/psiphon.config.backup /opt/psiphon-tun/psiphon/psiphon.config

# Service won't start after config change?
sudo systemctl status psiphon-tun -l
sudo journalctl -u psiphon-tun -n 20

# Changes not taking effect?
sudo systemctl reload psiphon-tun  # Don't use restart
```

---

For detailed parameter info, see main Psiphon documentation.
