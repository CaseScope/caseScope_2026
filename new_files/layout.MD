📊 CASESCOPE NAVIGATION TREE
│
├── 🔍 Search (existing - EVTX, EDR, Firewall, Sysmon)
│   └── Parsers: evtx_parser, ndjson_parser, firewall_csv_parser
│
├── 🌐 Browser History (existing)
│   └── Parsers: browser_history_parser, webcache_parser
│
├── ⚡ Execution Artifacts (existing)
│   └── Parsers: dissect_prefetch_parser, srum_parser, activities_parser
│
├── 📁 Filesystem Timeline (existing)
│   └── Parsers: eztools_mft_parser, thumbcache_parser, winsearch_parser
│
├── 👤 User Activity (NEW PAGE)
│   ├── Jump Lists
│   ├── LNK Files  
│   ├── Shellbags
│   └── Parsers: eztools_jumplist_parser, lnk_parser, eztools_lnk_parser
│
├── 💬 Communications (NEW PAGE)
│   ├── Email (PST/OST)
│   ├── Teams/Skype
│   └── Notifications
│   └── Parsers: pst_parser, teams_skype_parser, notifications_parser
│
├── 🌐 Network Activity (NEW PAGE)
│   ├── BITS Transfers
│   ├── Firewall (move from Search?)
│   └── Parsers: bits_parser, firewall_csv_parser
│
├── 🔒 Persistence (NEW PAGE)
│   ├── Scheduled Tasks
│   ├── WMI Subscriptions
│   └── Parsers: schtasks_parser, wmi_parser
│
├── 💾 Devices (NEW PAGE)
│   ├── USB History
│   └── Parsers: usb_history_parser, setupapi_parser
│
├── ☁️ Cloud Storage (NEW PAGE)
│   ├── OneDrive
│   └── Parsers: onedrive_parser
│
└── 🖥️ Remote Sessions (NEW PAGE)
    ├── RDP Cache
    └── Parsers: rdp_cache_parser

    Detailed Mapping
Page | Index Name | Parsers | Evidence Types
Search (existing)| case_X_events | evtx, ndjson, firewall_csv | Event logs, EDR, Sysmon
Browser History (existing) | case_X_browser | browser_history, webcache | URLs, downloads, cache
Execution Artifacts (existing) | case_X_execution | prefetch, srum, activities | Program runs, app usage, timeline
Filesystem Timeline (existing) | case_X_filesystem | mft, thumbcache, winsearch | Files, thumbnails, search index
User Activity (NEW)| case_X_useractivity | jumplist, lnk | Recent files, shortcuts
Communications (NEW) | case_X_comms | pst, teams_skype, notifications | Emails, chats, alerts
Network Activity (NEW) | case_X_network | bits, srum (network portion) | Downloads, transfers
Persistence (NEW) | case_X_persistence | schtasks, wmi | Scheduled tasks, WMI events
Devices (NEW) | case_X_devices | usb_history, setupapi | USB connections
Cloud Storage (NEW) | case_X_cloud | onedriveSync activity
Remote Sessions (NEW) | case_X_remote | rdp_cache | RDP evidence

Recommended Sidebar Icons
🔍 Search              (magnifying glass)
🌐 Browser History     (globe)
⚡ Execution           (lightning bolt)
📁 Filesystem          (folder)
👤 User Activity       (person)
💬 Communications      (chat bubble)
🌐 Network             (network/wifi)
🔒 Persistence         (lock/shield)
💾 Devices             (USB/drive)
☁️ Cloud               (cloud)
🖥️ Remote Sessions     (monitor/desktop)