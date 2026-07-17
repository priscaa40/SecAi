#!/bin/sh
set -eu

api_base="${SECAI_API_BASE_URL:-}"

escaped_api_base=$(printf '%s' "$api_base" | sed 's/\\/\\\\/g; s/"/\\"/g')
printf 'window.__SECAI_CONFIG__ = { apiBase: "%s" };\n' "$escaped_api_base" > /usr/share/nginx/html/config.js
