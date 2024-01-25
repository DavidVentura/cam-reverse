```mermaid
---
title: Establish session
---

sequenceDiagram
    App->>+Cam: LanSearch
    Cam->>-App: PunchPkt (SerialNo)
    App->>+Cam: P2PRdy
    Cam->>-App: P2PRdy
   
   loop Every 400-500ms
        Cam-->>+App: P2PAlive
        App-->>-Cam: P2PAliveAck
    end
```
