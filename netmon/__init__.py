"""netmon package -- Phase 1: home-network traffic monitor.

Watches this machine's network interface, rolls packets up into flow
metadata (who talked to who, on what port, how much data -- never packet
contents), detects suspicious patterns, watches for connection drops,
and explains what's happening in plain English.

Modules:
  db        -- SQLite storage (flows, alerts, outages, summaries)
  capture   -- packet capture -> flow metadata (live sniff or pcap file)
  detect    -- detection rules over recent traffic
  watchdog  -- ping-based connection drop detection
  explainer -- periodic plain-English AI summaries of network activity
  dashboard -- Flask live dashboard
  run       -- entry point wiring it all together
"""
