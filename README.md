# Whisper Evidence - BlackHat MEA Qualification CTF 2026

**Category:** Forensics  
**Difficulty:** Medium  
**Points:** TBD  
**Solves:** TBD  
**Author:** aintantony

## Challenge Description
A digital forensics investigation of an insider threat incident involving data exfiltration using AI-assisted techniques.

## Flag
```
BHFlagY{l0c4l_0ll4m4_llm_f4r3n51c5_2026}
```

## Files
- [WRITEUP.md](./WRITEUP.md) - Detailed solution walkthrough
- [solve.py](./solve.py) - Automated solution script

## Quick Solution
1. Found Ollama AI chat history with password: `Gr33nF0x42!D1amond`
2. Discovered exfiltration script in Trash deriving key with blake2b
3. Extracted encrypted archive at `.cache/fontconfig/session.zip`
4. Flag found base64-encoded in `internal_api_keys.csv`

## Tags
`forensics` `insider-threat` `encryption` `python` `AI-LLM` `data-exfiltration`
