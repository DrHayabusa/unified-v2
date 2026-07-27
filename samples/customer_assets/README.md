# Customer Asset Inventory Samples

These four inventories are intentionally different and map one customer workspace to one scanner source for local platform testing.

| Customer | Scanner history | Inventory focus | Responsible teams |
|---|---|---|---|
| `sample_1` | Tenable.sc | Linux, Windows, databases | Linux Operations, Windows Operations, Database Engineering |
| `sample_2` | Tenable.io | Network, security, virtualization | Network Operations, Security Engineering, Virtualization Team |
| `sample_3` | Qualys VMDR | Cloud, containers, endpoints | Cloud Platform, Container Platform, Endpoint Engineering |
| `sample_4` | CrowdStrike Spotlight | OT, virtualization, infrastructure | OT Operations, Virtualization Operations, Infrastructure Services |

Each CSV has eight unique assets and uses the supported normalized columns, including `Asset Type` and `Responsible Team`. The seed command creates missing teams, imports the inventory in strict inventory mode, and loads May, June, and July 2026 scanner history:

```bash
cd "/Users/mohammedshahid/Documents/New project/unified-tool"
DATABASE_URL='postgresql://mva@127.0.0.1:55432/mva' node tools/seed_sample_customers.mjs
```

The seed is idempotent. Its acceptance check requires every dashboard to reconcile to 13 current, 5 new, 4 fixed, and 8 repeated findings with a `12 -> 12 -> 13` three-month trend.
