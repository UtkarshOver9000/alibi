# Test fixtures

Saved from real feed responses (no generated data):

- `dbip-city-lite-head.csv.gz`: the first 1,000 rows of DB-IP IP to City Lite, October 2026.
  IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0.
- `raw/`: small excerpts of each feed as downloaded on 9 October 2026, for the parser tests:
  Have I Been Pwned (first 40 breaches, CC BY 4.0), CISA KEV (first 40 entries), abuse.ch Feodo Tracker,
  ThreatFox (60 indicator groups) and URLhaus (60 URLs) (CC0), Spamhaus DROP and ASN-DROP (30 lines each),
  RansomLook (40 posts, CC BY 4.0).
- `rba-sample.csv.gz`: 2,676 rows of the RBA login dataset (Wiefling et al., https://zenodo.org/records/6782156,
  CC BY 4.0) with its original column names, for the end-to-end training test: every login of the 257 users who
  have 5 to 30 logins and an ID divisible by 4,000, plus every login of the first 8 account-takeover users by ID
  (at most 40 logins each) in each of the train, validation and test windows. As the model card says, the
  dataset's values were synthesized by its authors from real logins; nothing here was changed or made up.
