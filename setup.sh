#!/bin/bash
#################### Simple Nginx + Self-Signed SSL Script ####################
[[ $EUID -ne 0 ]] && { echo "Run as root!"; exec sudo "$0" "$@"; }

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}===========================================${NC}"
echo -e "${GREEN} Nginx + SSL Setup Script ${NC}"
echo -e "${GREEN}===========================================${NC}"

# Get domain
while [[ -z "$domain" ]]; do
    read -p "Enter domain (e.g., example.com): " domain
done

MainDomain=$(echo "$domain" | sed 's/.*\.\([^.]*\.[^.]*\)$/\1/')
if [[ "$MainDomain" == "$domain" ]]; then
    MainDomain="$domain"
fi

echo -e "${BLUE}Domain: $domain${NC}"
echo -e "${BLUE}Main Domain: $MainDomain${NC}"

# Update packages
echo -e "${YELLOW}Updating packages...${NC}"
apt update -qq

# Install packages
echo -e "${YELLOW}Installing nginx and openssl...${NC}"
apt install -y nginx openssl unzip wget

# Stop nginx and clear ports
systemctl stop nginx 2>/dev/null
fuser -k 80/tcp 443/tcp 2>/dev/null

# Check nginx version for HTTP/2
nginx_ver=$(nginx -v 2>&1 | awk -F/ '{print $2}')
if [[ "$nginx_ver" < "1.25.1" ]]; then
    HTTP2_CONFIG=" http2"
    HTTP2_NEW="#"
else
    HTTP2_CONFIG=""
    HTTP2_NEW=""
fi

# Create directories
mkdir -p /etc/ssl/{certs,private} /var/www/html /etc/nginx/sites-{available,enabled}

# Generate self-signed certificate (5 years)
echo -e "${YELLOW}Generating 5-year self-signed SSL certificate...${NC}"
openssl req -x509 -nodes -days 1825 -newkey rsa:2048 \
  -keyout "/etc/ssl/private/privkey.pem" \
  -out "/etc/ssl/certs/fullchain.pem" \
  -subj "/CN=$MainDomain/O=Self-Signed" \
  -addext "subjectAltName=DNS:$MainDomain,DNS:*.$MainDomain" 2>/dev/null

chmod 600 /etc/ssl/private/privkey.pem
chmod 644 /etc/ssl/certs/fullchain.pem

echo -e "${GREEN}SSL certificate generated successfully!${NC}"

# Create nginx.conf
cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
worker_rlimit_nofile 65535;

events {
    worker_connections 65535;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml+rss application/json;
    
    include /etc/nginx/sites-enabled/*;
}
EOF

# Create site config
cat > "/etc/nginx/sites-available/$MainDomain" << EOF
server {
    listen 80;
    listen [::]:80;
    server_name $MainDomain *.$MainDomain;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl${HTTP2_CONFIG};
    listen [::]:443 ssl${HTTP2_CONFIG};
    ${HTTP2_NEW}http2 on;
    
    server_name $MainDomain *.$MainDomain;
    root /var/www/html;
    index index.html index.htm;
    
    # SSL Configuration
    ssl_certificate /etc/ssl/certs/fullchain.pem;
    ssl_certificate_key /etc/ssl/private/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Security
    if (\$host !~* ^(.+\.)?$MainDomain\$ ) { return 444; }
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # Block common attack patterns
    location ~* \.(php|jsp|asp)$ { return 444; }
    location ~* /\.(ht|git|svn) { return 444; }
}
EOF

# Enable site
rm -f /etc/nginx/sites-enabled/default
ln -sf "/etc/nginx/sites-available/$MainDomain" /etc/nginx/sites-enabled/

# Test nginx config
if ! nginx -t; then
    echo -e "${RED}Nginx configuration error!${NC}"
    exit 1
fi

# Create simple index page
cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Server Ready</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0; padding: 0; min-height: 100vh;
            display: flex; align-items: center; justify-content: center;
            color: white;
        }
        .container {
            text-align: center;
            background: rgba(255,255,255,0.1);
            padding: 3rem; border-radius: 15px;
            backdrop-filter: blur(10px);
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
        }
        h1 { font-size: 3rem; margin-bottom: 1rem; }
        p { font-size: 1.2rem; opacity: 0.9; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Server Ready</h1>
        <p>Nginx with SSL is running successfully</p>
    </div>
</body>
</html>
EOF

# Download and install random fake website
echo -e "${YELLOW}Installing random fake website template...${NC}"
cd /tmp
if wget -q https://github.com/GFW4Fun/randomfakehtml/archive/refs/heads/master.zip; then
    unzip -q master.zip
    if [[ -d "randomfakehtml-master" ]]; then
        cd randomfakehtml-master
        # Remove unnecessary files
        rm -rf assets .gitattributes README.md _config.yml 2>/dev/null
        # Get random template
        TEMPLATE=$(find . -maxdepth 1 -type d ! -name "." | sed 's|^\./||' | shuf -n1)
        if [[ -n "$TEMPLATE" && -d "$TEMPLATE" ]]; then
            echo -e "${BLUE}Installing template: $TEMPLATE${NC}"
            rm -rf /var/www/html/*
            cp -r "$TEMPLATE"/* /var/www/html/ 2>/dev/null
            chown -R www-data:www-data /var/www/html/
            echo -e "${GREEN}Random template installed successfully!${NC}"
        fi
    fi
fi
cd /root
rm -rf /tmp/randomfakehtml-master /tmp/master.zip

# Set permissions
chown -R www-data:www-data /var/www/html/
chmod -R 755 /var/www/html/

# Start nginx
systemctl enable nginx
systemctl start nginx

# Add cron job for nginx maintenance
(crontab -l 2>/dev/null; echo "0 0 * * * systemctl reload nginx") | crontab -

# Show results
clear
echo -e "${GREEN}===========================================${NC}"
echo -e "${GREEN} Setup Complete! ${NC}"
echo -e "${GREEN}===========================================${NC}"
echo -e "${BLUE}✅ Nginx installed and running${NC}"
echo -e "${BLUE}✅ SSL certificate configured (5 years)${NC}"
echo -e "${BLUE}✅ Random fake website installed${NC}"
echo -e "${BLUE}✅ Security headers configured${NC}"
echo -e "${BLUE}✅ Maintenance cron job added${NC}"
echo -e "${GREEN}===========================================${NC}"
echo -e "${YELLOW}🌐 Your site: https://$domain${NC}"
echo -e "${YELLOW}⚠️  Self-signed cert: browsers show 'Not Secure'${NC}"
echo -e "${YELLOW}   but connection is encrypted (click 'Advanced' → 'Proceed')${NC}"
echo -e "${GREEN}===========================================${NC}"

# Show certificate info
echo -e "${BLUE}Certificate details:${NC}"
openssl x509 -in /etc/ssl/certs/fullchain.pem -text -noout | grep -E "Subject:|Not After:|DNS:" | head -5

echo -e "${GREEN}Done! 🎉${NC}"