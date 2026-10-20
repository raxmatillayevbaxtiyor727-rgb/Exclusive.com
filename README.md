# EXCLUSIVE — Netlify admin backend

## Papkalar

- `admin/index.html` — admin panel
- `netlify/functions/api.js` — API va admin backend
- `netlify.toml` — Netlify Functions va `/api/*` routing
- `package.json` — Netlify Blobs dependency

## Netlify Environment Variables

Netlify → Site configuration → Environment variables:

`SETUP_KEY` = o'zingiz belgilaydigan maxfiy birinchi sozlash kaliti

Ixtiyoriy:

`TELEGRAM_BOT_TOKEN`
`TELEGRAM_CHAT_ID`

Birinchi marta `/admin/` sahifasiga kirib, SETUP_KEY orqali admin hisobini yarating.

## Muhim

Agar eski admin hisob allaqachon Netlify Blobs ichida mavjud bo'lsa, yangi SETUP_KEY bilan qayta hisob yaratish ishlamaydi. Eski admin parolini almashtirish uchun mavjud admin paroli kerak bo'ladi.
