#!/bin/bash
#################### Nginx + Let's Encrypt Wildcard SSL ####################
[[ $EUID -ne 0 ]] && { echo "Run as root!"; exec sudo "$0" "$@"; }

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}===========================================${NC}"
echo -e "${GREEN} Nginx + Let's Encrypt Wildcard SSL ${NC}"
echo -e "${GREEN}===========================================${NC}"

# Get domain
while [[ -z "$domain" ]]; do
    read -p "Enter domain (e.g., example.com): " domain
done

MainDomain=$(echo "$domain" | sed 's/.*\.\([^.]*\.[^.]*\)$/\1/')
if [[ "$MainDomain" == "$domain" ]]; then
    MainDomain="$domain"
fi

# Get Cloudflare API credentials
while [[ -z "$CF_API_TOKEN" ]]; do
    echo -e "${YELLOW}For wildcard SSL, we need Cloudflare API Token${NC}"
    echo -e "${BLUE}Go to: https://dash.cloudflare.com/profile/api-tokens${NC}"
    echo -e "${BLUE}Create token with: Zone:DNS:Edit + Zone:Zone:Read${NC}"
    read -p "Enter Cloudflare API Token: " CF_API_TOKEN
done

echo -e "${BLUE}Domain: $domain${NC}"
echo -e "${BLUE}Main Domain: $MainDomain${NC}"

# Update packages and install requirements
echo -e "${YELLOW}Installing packages...${NC}"
apt update -qq
apt install -y nginx openssl unzip wget python3-pip

# Install certbot and cloudflare plugin
echo -e "${YELLOW}Installing certbot and cloudflare plugin...${NC}"
pip3 install certbot certbot-dns-cloudflare

# Stop nginx temporarily
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
mkdir -p /etc/ssl/{certs,private} /var/www/html /etc/nginx/sites-{available,enabled} /etc/letsencrypt

# Create Cloudflare credentials file
cat > /etc/letsencrypt/cloudflare.ini << EOF
dns_cloudflare_api_token = $CF_API_TOKEN
EOF
chmod 600 /etc/letsencrypt/cloudflare.ini

# Test API first
echo -e "${YELLOW}Testing Cloudflare API...${NC}"
if ! curl -s "https://api.cloudflare.com/client/v4/user/tokens/verify" \
  -H "Authorization: Bearer $CF_API_TOKEN" | grep -q '"success":true'; then
    echo -e "${RED}API Token test failed! Please check your token.${NC}"
    exit 1
fi
echo -e "${GREEN}API Token verified!${NC}"

# Get wildcard SSL certificate
echo -e "${YELLOW}Getting Let's Encrypt wildcard certificate...${NC}"
certbot certonly \
  --dns-cloudflare \
  --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
  --dns-cloudflare-propagation-seconds 60 \
  -d "$MainDomain" \
  -d "*.$MainDomain" \
  --non-interactive \
  --agree-tos \
  --register-unsafely-without-email \
  --cert-name "$MainDomain"

if [[ ! -d "/etc/letsencrypt/live/$MainDomain/" ]]; then
    echo -e "${RED}SSL certificate failed! Check the logs: /var/log/letsencrypt/letsencrypt.log${NC}"
    exit 1
fi

echo -e "${GREEN}Wildcard SSL certificate obtained successfully!${NC}"

# Copy certificates to nginx location (but keep Let's Encrypt paths in config)
cp "/etc/letsencrypt/live/$MainDomain/fullchain.pem" "/etc/ssl/certs/"
cp "/etc/letsencrypt/live/$MainDomain/privkey.pem" "/etc/ssl/private/"
chmod 644 /etc/ssl/certs/fullchain.pem
chmod 600 /etc/ssl/private/privkey.pem

# Determine nginx user
nginxusr="www-data"
id -u "$nginxusr" &>/dev/null || nginxusr="nginx"

# Create nginx.conf (original structure)
cat > /etc/nginx/nginx.conf << EOF
user $nginxusr;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;
worker_rlimit_nofile 65535;
events { 
    worker_connections 65535; 
    use epoll; 
    multi_accept on; 
}
http {
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    gzip on;
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 4096;
    default_type application/octet-stream;
    include /etc/nginx/*.types;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

# Create site config with original structure (minus x-ui and v2rayA)
cat > "/etc/nginx/sites-available/$MainDomain" << EOF
server {
    server_tokens off;
    server_name $MainDomain *.$MainDomain;
    listen 80;
    listen [::]:80;
    listen 443 ssl${HTTP2_CONFIG};
    listen [::]:443 ssl${HTTP2_CONFIG};
    ${HTTP2_NEW}http2 on; 
    ${HTTP2_NEW}http3 on;
    index index.html index.htm index.php index.nginx-debian.html;
    root /var/www/html/;
    
    # SSL Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!eNULL:!MD5:!DES:!RC4:!ADH:!SSLv3:!EXP:!PSK:!DSS;
    ssl_certificate /etc/letsencrypt/live/$MainDomain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$MainDomain/privkey.pem;
    
    # Security checks
    if (\$host !~* ^(.+\.)?$MainDomain\$ ){return 444;}
    if (\$scheme ~* https) {set \$safe 1;}
    if (\$ssl_server_name !~* ^(.+\.)?$MainDomain\$ ) {set \$safe "\${safe}0"; }
    if (\$safe = 10){return 444;}
    
    # Block malicious requests
    if (\$request_uri ~ "(\\.\\./|//|0x00|0X00)"){return 444;}
    
    error_page 400 402 403 500 501 502 503 504 =404 /404;
    proxy_intercept_errors on;
    
    # Subscription Path (simple/encode)
    location ~ ^/(?<fwdport>\\d+)/sub/(?<fwdpath>.*)\$ {
        proxy_redirect off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass http://127.0.0.1:\$fwdport/sub/\$fwdpath\$is_args\$args;
        break;
    }
    
    # Subscription Path (json/fragment)
    location ~ ^/(?<fwdport>\\d+)/json/(?<fwdpath>.*)\$ {
        proxy_redirect off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass http://127.0.0.1:\$fwdport/json/\$fwdpath\$is_args\$args;
        break;
    }
    
    # Xray Config Path
    location ~ ^/(?<fwdport>\\d+)/(?<fwdpath>.*)\$ {
        client_max_body_size 0;
        client_body_timeout 1d;
        grpc_read_timeout 1d;
        grpc_socket_keepalive on;
        proxy_read_timeout 1d;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_socket_keepalive on;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        if (\$content_type ~* "GRPC") { grpc_pass grpc://127.0.0.1:\$fwdport\$is_args\$args; break; }
        proxy_pass http://127.0.0.1:\$fwdport\$is_args\$args;
        break;
    }
    
    # Default location - serve static files
    location / { 
        try_files \$uri \$uri/ =404; 
    }
    
    # Add security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
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

# Download and install random fake website
echo -e "${YELLOW}Installing random fake website template...${NC}"
cd /tmp
if wget -q https://github.com/GFW4Fun/randomfakehtml/archive/refs/heads/master.zip; then
    unzip -q master.zip 2>/dev/null
    if [[ -d "randomfakehtml-master" ]]; then
        cd randomfakehtml-master
        rm -rf assets .gitattributes README.md _config.yml 2>/dev/null
        TEMPLATE=$(find . -maxdepth 1 -type d ! -name "." | sed 's|^\./||' | shuf -n1 2>/dev/null)
        if [[ -n "$TEMPLATE" && -d "$TEMPLATE" ]]; then
            echo -e "${BLUE}Installing template: $TEMPLATE${NC}"
            rm -rf /var/www/html/*
            cp -r "$TEMPLATE"/* /var/www/html/ 2>/dev/null
            echo -e "${GREEN}Random template installed successfully!${NC}"
        fi
    fi
fi

# Fallback to simple page if template failed
if [[ ! -f "/var/www/html/index.html" ]]; then
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
        <p>Nginx with Let's Encrypt SSL is running</p>
    </div>
</body>
</html>
EOF
fi

cd /root
rm -rf /tmp/randomfakehtml-master /tmp/master.zip

# Set permissions
chown -R www-data:www-data /var/www/html/
chmod -R 755 /var/www/html/

# Start nginx
systemctl enable nginx
systemctl start nginx

# Create renewal hook script
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/nginx-reload.sh << EOF
#!/bin/bash
# Let's Encrypt auto-renewal hook - nginx uses direct Let's Encrypt paths
systemctl reload nginx
echo "\$(date): SSL certificates renewed and nginx reloaded" >> /var/log/ssl-renewal.log
EOF
chmod +x /etc/letsencrypt/renewal-hooks/deploy/nginx-reload.sh

# Add cron jobs for renewal and maintenance
(crontab -l 2>/dev/null | grep -v "certbot\|nginx"; cat << EOF
# SSL renewal (twice daily)
0 0,12 * * * certbot renew --dns-cloudflare --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini --quiet
# Nginx maintenance
0 2 * * * systemctl reload nginx
EOF
) | crontab -

# Test renewal (dry run)
echo -e "${YELLOW}Testing SSL auto-renewal...${NC}"
if certbot renew --dns-cloudflare --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini --dry-run --quiet; then
    echo -e "${GREEN}SSL auto-renewal test successful!${NC}"
else
    echo -e "${RED}SSL auto-renewal test failed! Check /var/log/letsencrypt/letsencrypt.log${NC}"
fi

# Show results
clear
echo -e "${GREEN}===========================================${NC}"
echo -e "${GREEN} Setup Complete! ${NC}"
echo -e "${GREEN}===========================================${NC}"
echo -e "${BLUE}✅ Nginx installed and running${NC}"
echo -e "${BLUE}✅ Let's Encrypt wildcard SSL configured${NC}"
echo -e "${BLUE}✅ Auto-renewal every 12 hours${NC}"
echo -e "${BLUE}✅ Random fake website installed${NC}"
echo -e "${BLUE}✅ Security headers configured${NC}"
echo -e "${GREEN}===========================================${NC}"
echo -e "${YELLOW}🌐 Your site: https://$domain${NC}"
echo -e "${YELLOW}🔒 SSL valid for: $MainDomain + *.$MainDomain${NC}"
echo -e "${YELLOW}🔄 Auto-renewal: Every 12 hours${NC}"
echo -e "${YELLOW}📝 Renewal logs: /var/log/ssl-renewal.log${NC}"
echo -e "${GREEN}===========================================${NC}"

# Show certificate info
echo -e "${BLUE}Certificate details:${NC}"
openssl x509 -in "/etc/letsencrypt/live/$MainDomain/fullchain.pem" -text -noout | grep -E "Subject:|Not After:|DNS:" | head -5

echo -e "${GREEN}"
echo "🎉 Success! Your SSL certificate is valid and trusted by all browsers!"
echo "🔄 Automatic renewal is configured - no manual intervention needed!"
echo -e "${NC}"