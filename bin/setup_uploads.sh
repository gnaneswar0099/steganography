#!/bin/bash

# This startup script runs before nginx starts on Azure App Service Linux
# It ensures nginx and PHP have proper file upload limits

echo "Setting up upload limit configuration..."

# 1. Ensure PHP-FPM gets the right settings
mkdir -p /usr/local/etc/php/conf.d
cat > /usr/local/etc/php/conf.d/uploads.ini <<EOF
upload_max_filesize = 50M
post_max_size = 50M
memory_limit = 512M
max_input_time = 300
default_socket_timeout = 60
EOF

echo "PHP configuration created"

# 2. Create nginx configuration for large uploads
mkdir -p /etc/nginx/conf.d
cat > /etc/nginx/conf.d/client_max_body_size.conf <<EOF
client_max_body_size 50M;
EOF

echo "Nginx configuration created"

# 3. Also add to main http block if possible (will be applied when nginx reloads)
if [ -f "/etc/nginx/nginx.conf" ]; then
    if ! grep -q "client_max_body_size" /etc/nginx/nginx.conf; then
        sed -i '/http {/a\    client_max_body_size 50M;' /etc/nginx/nginx.conf 2>/dev/null || true
    fi
fi

echo "Upload limits configured successfully"
