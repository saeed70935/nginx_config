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

# Get Cloudflare API credentials for DNS challenge
while [[ -z "$CF_API_TOKEN" ]]; do
    echo -e "${YELLOW}For wildcard SSL, we need Cloudflare API Token${NC}"
    echo -e "${BLUE}Go to: https://dash.cloudflare.com/profile/api-tokens${NC}"
    echo -e "${BLUE}Create token with: Zone:DNS:Edit + Zone:Zone:Read${NC}"
    read -p "Enter Cloudflare API Token: " CF_API_TOKEN
done

while [[ -z "$CF_ZONE_ID" ]]; do
    echo -e "${BLUE}Get Zone ID from Cloudflare Dashboard (right sidebar)${NC}"
    read -p "Enter Cloudflare Zone ID: " CF_ZONE_ID
done

echo -e "${BLUE}Domain: $domain${NC}"
echo -e "${BLUE}Main Domain: $MainDomain${NC}"

# Update packages
echo -e "${YELLOW}Installing packages...${NC}"
apt update -qq
apt install -y nginx openssl unzip wget python3-pip

# Install certbot and cloudflare plugin
pip3 install certbot certbot-dns-cloudflare

# Stop nginx temporarily for initial setup
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

# Create Cloudflare credentials file for certbot
mkdir -p /etc/letsencrypt
cat > /etc/letsencrypt/cloudflare.ini << EOF
dns_cloudflare_api_token = $CF_API_TOKEN
EOF
chmod 600 /etc/letsencrypt/cloudflare.ini

# Get wildcard SSL certificate using DNS challenge
echo -e "${YELLOW}Getting Let's Encrypt wildcard certificate...${NC}"
certbot certonly \
  --dns-cloudflare \
  --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
  --dns-cloudflare-propagation-seconds 30 \
  -d "$MainDomain" \
  -d "*.$MainDomain" \
  --non-interactive \
  --agree-tos \
  --register-unsafely-without-email \
  --cert-name "$MainDomain"

if [[ ! -d "/etc/letsencrypt/live/$MainDomain/" ]]; then
    echo -e "${RED}SSL certificate failed! Check API credentials!${NC}"
    exit 1
fi

echo -e "${GREEN}Wildcard SSL certificate obtained successfully!${NC}"

# Copy certificates to standard location
cp "/etc/letsencrypt/live/$MainDomain/fullchain.pem" "/etc/ssl/certs/"
cp "/etc/letsencrypt/live/$MainDomain/privkey.pem" "/etc/ssl/private/"
chmod 644 /etc/ssl/certs/fullchain.pem
chmod 600 /etc/ssl/private/privkey.pem

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
    
    # ACME challenge for Let's Encrypt renewal
    location /.well-known/acme-challenge/ {
        root /var/www/html;
        try_files \$uri \$uri/ =404;
    }
    
    # Redirect everything else to HTTPS
    location / {
        return 301 https://\$server_name\$request_uri;
    }
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

# Download and install random fake website
echo -e "${YELLOW}Installing random fake website template...${NC}"
cd /tmp
if wget -q https://github.com/GFW4Fun/randomfakehtml/archive/refs/heads/master.zip; then
    unzip -q master.zip
    if [[ -d "randomfakehtml-master" ]]; then
        cd randomfakehtml-master
        rm -rf assets .gitattributes README.md _config.yml 2>/dev/null
        TEMPLATE=$(find . -maxdepth 1 -type d ! -name "." | sed 's|^\./||' | shuf -n1)
        if [[ -n "$TEMPLATE" && -d "$TEMPLATE" ]]; then
            echo -e "${BLUE}Installing template: $TEMPLATE${NC}"
            rm -rf /var/www/html/*
            cp -r "$TEMPLATE"/* /var/www/html/ 2>/dev/null
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

# Create renewal script that updates nginx certificates
cat > /etc/letsencrypt/renewal-hooks/deploy/nginx-reload.sh << EOF
#!/bin/bash
# Copy renewed certificates to nginx location
cp "/etc/letsencrypt/live/$MainDomain/fullchain.pem" "/etc/ssl/certs/"
cp "/etc/letsencrypt/live/$MainDomain/privkey.pem" "/etc/ssl/private/"
chmod 644 /etc/ssl/certs/fullchain.pem
chmod 600 /etc/ssl/private/privkey.pem
systemctl reload nginx
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
echo -e "${YELLOW}Testing SSL renewal...${NC}"
if certbot renew --dns-cloudflare --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini --dry-run; then
    echo -e "${GREEN}SSL renewal test successful!${NC}"
else
    echo -e "${RED}SSL renewal test failed!${NC}"
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
echo -e "${GREEN}===========================================${NC}"

# Show certificate info
echo -e "${BLUE}Certificate details:${NC}"
openssl x509 -in /etc/ssl/certs/fullchain.pem -text -noout | grep -E "Subject:|Not After:|DNS:" | head -5

echo -e "${GREEN}Done! SSL will auto-renew without interrupting nginx! 🎉${NC}"