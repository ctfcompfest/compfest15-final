# Writeup - Writeup Editor

Vulnerability list:
- LFI on module fs (https://brycec.me/posts/corctf_2022_challenges#simplewaf)
- RCE by uploading arbitrary script on `src/pages/api` directory through `save` endpoint and LFI bug
- LFI using XSS through "file://" protocol in markdown to pdf conversion