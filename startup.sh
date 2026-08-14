#!/bin/bash
# ============================================================
# startup.sh — Azure App Service PHP startup script
# Azure overwrites /etc/nginx/sites-enabled/default AFTER
# this script runs, so we write our config AND schedule a
# background reload to apply it after nginx has started.
# ============================================================

echo "[startup] Writing secure nginx config..."

write_nginx_config() {
cat > /etc/nginx/sites-enabled/default << 'NGINXEOF'
server {
    listen 8080;
    listen [::]:8080;
    root /home/site/wwwroot;
    index index.php index.html index.htm;
    server_name example.com www.example.com;
    port_in_redirect off;

    # ─── Security Headers ─────────────────────────────────────────────────
    server_tokens off;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data:; frame-ancestors 'none';" always;
    # ──────────────────────────────────────────────────────────────────────

    # SECURITY: Block dotfiles (.env, .htaccess, .git, etc.)
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }

    # SECURITY: Block sensitive PHP backend files
    location ~ ^/(app_config|db|crypto|lsb|prng|payload|nav|error_session|predict_compression)\.php$ {
        deny all;
        return 404;
    }

    # SECURITY: Block sensitive config/build files
    location ~ ^/(composer\.json|composer\.lock|requirements\.txt|database_schema\.sql|oryx-manifest\.toml|startup\.sh)$ {
        deny all;
        return 404;
    }

    # SECURITY: Block bin/ and vendor/ directories
    location ^~ /bin/ {
        deny all;
        return 404;
    }

    location ^~ /vendor/ {
        deny all;
        return 404;
    }

    location / {
        index index.php index.html index.htm hostingstart.html;
    }

    error_page 500 502 503 504 /50x.html;
    location = /50x.html {
        root /html/;
    }

    location ~* [^/]\.php(/|$) {
        fastcgi_split_path_info ^(.+?\.[Pp][Hh][Pp])(|/.*)$;
        fastcgi_pass 127.0.0.1:9000;
        include fastcgi_params;
        fastcgi_param HTTP_PROXY "";
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param PATH_INFO $fastcgi_path_info;
        fastcgi_param QUERY_STRING $query_string;
        fastcgi_intercept_errors on;
        fastcgi_connect_timeout 300;
        fastcgi_send_timeout 3600;
        fastcgi_read_timeout 3600;
        fastcgi_buffer_size 128k;
        fastcgi_buffers 4 256k;
        fastcgi_busy_buffers_size 256k;
        fastcgi_temp_file_write_size 256k;
        fastcgi_hide_header X-Powered-By;
    }
}
NGINXEOF
}

# Write config now (before nginx starts)
write_nginx_config

# Upload limits
cat > /etc/nginx/conf.d/upload_limits.conf << 'EOF'
client_max_body_size 50M;
EOF

# Background process: wait for nginx to start, then write config again
# and reload — this handles the case where Azure overwrites our config
# after this script exits.
(
    sleep 15
    write_nginx_config
    nginx -s reload
    echo "[startup] nginx reloaded with security rules at $(date)"
) &

echo "[startup] Done. Security rules applied and background reload scheduled."
