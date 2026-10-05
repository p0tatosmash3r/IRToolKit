# Tests/SampleData/Common

Real `.evtx` fixtures used by the shared-module tests under `Tests/Common`. Everything else in
`Tests/SampleData` is synthetic JSON; these are kept as binary logs because the behaviour under test
only shows up in the native reader.

| File | Origin | Why it is here |
|---|---|---|
| `MalformedXmlRecord.evtx` | `ID4742-4743-Fast created & deleted computer account.evtx` from the public [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) corpus (CC0 1.0, public domain), unmodified | Contains a record that makes an event-ID-filtered `Get-WinEvent` throw a terminating `EventLogException` ("The specified XML text was not well-formed") while an unfiltered read succeeds. Regression fixture for `Get-IRWinEvent`'s isolated file read: 3 events (4742 / 4743) must come back with zero errors. |
