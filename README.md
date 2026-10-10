# echoes-ai-server

Secure backend for the **Ecos of the past** assistant.

- `POST /api/chat` — proxies the dialogue to Groq. The flag, code and document
  are **never** sent to the model, so prompt injection cannot leak them.
- Admin impersonation (the intended solution) is detected server-side with a
  string/regex match; only then is the flag returned.
- Per-IP rate limiting (15s between messages).
- `GET /api/download?code=...` — streams the gated document when the code matches.

All secrets are provided through environment variables (see `.env.example`):
`GROQ_API_KEY`, `GROQ_MODEL`, `FLAG`, `DOWNLOAD_CODE`, `DOCX_B64`,
`RATE_LIMIT_MS`, `ALLOWED_ORIGIN`.
