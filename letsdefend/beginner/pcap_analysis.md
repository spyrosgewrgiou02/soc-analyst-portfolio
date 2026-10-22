# Lab 003: Network Traffic & PCAP Forensics

- **Platform:** LetsDefend
- **Focus:** Wireshark Packet Analysis, TCP Stream Reconstruction, HTTP POST Exfiltration
- **Date completed:** 22/10/2026

## Scenario
Traffic was captured from an internal workstation belonging to user P13 (`Pcap_Analysis.pcapng`). The objective is to analyze the packet capture using Wireshark to reconstruct communication channels, track down unencrypted communications, and analyze an outbound HTTP file upload to an external web server.

## Investigation
1. **Unencrypted TCP Chat Identification:** Filtered traffic for unencrypted text streams (`frame contains "P13"`). Following the raw TCP stream revealed an unencrypted peer-to-peer dialogue between P13 and an external entity discussing file encryption.
2. **HTTP POST Analysis:** Filtered for outbound web uploads using `http.request.method == "POST"`. Located packet `3513` targeting `/panel.php`, originating from P13 and destined for a web server.
3. **MIME Multipart Inspection:** Followed the HTTP stream of the POST request to inspect the `multipart/form-data` boundary. Examined the `Content-Disposition` header to identify the uploaded payload.
4. **Server Fingerprinting & Upload Path:** Analyzed the `HTTP/1.1 200 OK` response payload to inspect the `Server` banner and parse the server's confirmation message for the server-side directory structure.
5. **Connection Metric Calculation:** Navigated to **Statistics → Conversations → TCP** to locate the conversation pair between P13 and the web server, recording the exact transfer duration.

## Findings
- **Sender & Receiver Chat IPs:** `192.168.235.137,192.168.235.131` (P13 and peer)
- **Web Server IP:** `192.168.1.7`
- **Uploaded File Name:** `file` (found via `Content-Disposition: form-data; name="file"; filename="file"`)
- **Web Server Software:** `Apache` (Apache/2.4.54 Win64)
- **Target Upload Directory:** `uploads` (parsed from `file uploaded at uploads/file`)
- **File Transfer Duration:** `0.0073` seconds

## Conclusion
**True Positive.** The capture confirms data movement across two distinct channels: an unencrypted interactive session between `192.168.235.137` and `192.168.235.131`, followed by an HTTP POST transmission of an encrypted binary named `file` to an Apache web server (`192.168.1.7`) into the `/uploads/` directory.

## Recommended response
- Restrict unencrypted outbound socket connections at the perimeter firewall.
- Block inbound and outbound communication to `192.168.1.7` across edge gateways.
- Extract the raw binary payload from the POST request MIME boundary in Wireshark for static analysis, hashing, and sandboxing.

## What I learned
- How to isolate clear-text application traffic and reconstruct full sessions using **Follow TCP Stream**.
- How to analyze `multipart/form-data` payloads within HTTP POST transactions to extract filenames and destination parameters.
- How to utilize **Statistics → Conversations** to extract forensic session metrics like transfer duration and packet volume.

## References
- [LetsDefend — PCAP Analysis Challenge](https://app.letsdefend.io/)
