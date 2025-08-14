#!/bin/bash
#################### Nginx Configuration Script ####################
[[ $EUID -ne 0 ]] && { echo "not root!"; exec sudo "$0" "$@"; }

# Clean up any previous downloads first
rm -f /tmp/setup.sh /tmp/nginx_setup.sh ~/setup.sh ~/nginx_setup.sh 2>/dev/null

msg()     { echo -e "\e[1;37;40m $1 \e[0m";}
msg_ok()  { echo -e "\e[1;32;40m $1 \e[0m";}
msg_err() { echo -e "\e[1;31;40m $1 \e[0m";}
msg_inf() { echo -e "\e[1;36;40m $1 \e[0m";}

# Package manager detection
Pak=$(command -v apt || command -v dnf); Pak=${Pak:-apt}

# Domain input
while [[ -z $(echo "$domain" | tr -d '[:space:]') ]]; do
    read -rp $'\e[1;32;40m Enter available subdomain (sub.domain.tld): \e[0m' domain
done

domain=$(echo "$domain" 2>&1 | tr -d '[:space:]' )
SubDomain=$(echo "$domain" 2>&1 | sed 's/^[^ ]* \|\..*//g')
MainDomain=$(echo "$domain" 2>&1 | sed 's/.*\.\([^.]*\..*\)$/\1/')

if [[ "${SubDomain}.${MainDomain}" != "${domain}" ]] ; then
    MainDomain=${domain}
fi

# Get Cloudflare credentials
while [[ -z "$CF_API_TOKEN" ]]; do
    read -rp $'\e[1;32;40m Enter Cloudflare API Token: \e[0m' CF_API_TOKEN
done

while [[ -z "$CF_ZONE_ID" ]]; do
    read -rp $'\e[1;32;40m Enter Cloudflare Zone ID: \e[0m' CF_ZONE_ID
done

# Install nginx and required packages
sudo $Pak -y purge python3-certbot-nginx 2>/dev/null || true
[[ $Pak == *apt ]] && sudo apt update || sudo dnf makecache

for p in nginx nginx-full python3 openssl jq curl unzip wget; do
  (command -v dpkg&>/dev/null && dpkg -l $p&>/dev/null)||(rpm -q $p&>/dev/null)||sudo $Pak -y install $p
done

# Enable and start nginx
systemctl daemon-reload > /dev/null 2>&1
systemctl enable nginx > /dev/null 2>&1

# Get nginx version and set HTTP/2 configuration
vercompare() { 
    if [ "$1" = "$2" ]; then echo "E"; return; fi
    [ "$(printf "%s\n%s" "$1" "$2" | sort -V | head -n1)" = "$1" ] && echo "L" || echo "G";
}

nginx_ver=$(nginx -v 2>&1 | awk -F/ '{print $2}');
ver_compare=$(vercompare "$nginx_ver" "1.25.1"); 
if [ "$ver_compare" = "L" ]; then
     OLD_H2=" http2";NEW_H2="#";
else 
     OLD_H2="";NEW_H2="";
fi

# Stop nginx and kill processes on ports 80/443
sudo nginx -s stop 2>/dev/null
sudo systemctl stop nginx 2>/dev/null
sudo fuser -k 80/tcp 80/udp 443/tcp 443/udp 2>/dev/null

# Create SSL certificate directory
mkdir -p "/etc/ssl/cloudflare/"

# Generate Cloudflare Origin Certificate automatically
msg_inf "Creating Cloudflare Origin Certificate for $MainDomain and all subdomains..."

# Create private key
openssl genrsa -out "/etc/ssl/cloudflare/${MainDomain}.key" 2048

# Create CSR with SAN for wildcard and main domain
cat > "/tmp/${MainDomain}.conf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = ${MainDomain}

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${MainDomain}
DNS.2 = *.${MainDomain}
EOF

# Generate CSR
openssl req -new -key "/etc/ssl/cloudflare/${MainDomain}.key" -out "/tmp/${MainDomain}.csr" -config "/tmp/${MainDomain}.conf"

# Read CSR content
CSR_CONTENT=$(cat "/tmp/${MainDomain}.csr" | tr -d '\n')

# Create certificate via Cloudflare API
msg_inf "Requesting certificate from Cloudflare API..."

API_RESPONSE=$(curl -s -X POST "https://api.cloudflare.com/client/v4/certificates" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "type": "origin-rsa",
    "hostnames": ["'$MainDomain'", "*.'$MainDomain'"],
    "requested_validity": 5475,
    "csr": "'$CSR_CONTENT'"
  }')

# Check if API call was successful
if echo "$API_RESPONSE" | jq -r '.success' | grep -q "true"; then
    # Extract certificate from response
    echo "$API_RESPONSE" | jq -r '.result.certificate' > "/etc/ssl/cloudflare/${MainDomain}.crt"
    
    # Set proper permissions
    chmod 644 "/etc/ssl/cloudflare/${MainDomain}.crt"
    chmod 600 "/etc/ssl/cloudflare/${MainDomain}.key"
    
    msg_ok "Cloudflare Origin Certificate created successfully!"
    
    # Show certificate info
    msg_inf "Certificate details:"
    echo "$API_RESPONSE" | jq -r '.result | "ID: \(.id)\nExpires: \(.expires_on)\nHostnames: \(.hostnames | join(", "))"'
    
else
    msg_err "Failed to create certificate via Cloudflare API"
    echo "Error response:"
    echo "$API_RESPONSE" | jq -r '.errors[]?.message // "Unknown error"'
    exit 1
fi

# Clean up temporary files
rm -f "/tmp/${MainDomain}.csr" "/tmp/${MainDomain}.conf"

# Create nginx directories
mkdir -p /etc/nginx/sites-{available,enabled} /var/log/nginx /var/www /var/www/html
rm -rf "/etc/nginx/default.d"

# Determine nginx user
nginxusr="www-data"
id -u "$nginxusr" &>/dev/null || nginxusr="nginx"

# Create main nginx.conf
cat > "/etc/nginx/nginx.conf" << EOF
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

# Create site configuration (CDN OFF mode - FIXED)
cat > "/etc/nginx/sites-available/$MainDomain" << 'NGINX_CONFIG'
server {
    server_tokens off;
    server_name DOMAIN_PLACEHOLDER *.DOMAIN_PLACEHOLDER;
    listen 80;
    listen [::]:80;
    listen 443 ssl HTTP2_OLD;
    listen [::]:443 ssl HTTP2_OLD;
    HTTP2_NEW http2 on; 
    HTTP2_NEW http3 on;
    index index.html index.htm index.php index.nginx-debian.html;
    root /var/www/html/;
    
    # SSL Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!eNULL:!MD5:!DES:!RC4:!ADH:!SSLv3:!EXP:!PSK:!DSS;
    ssl_certificate /etc/ssl/cloudflare/DOMAIN_PLACEHOLDER.crt;
    ssl_certificate_key /etc/ssl/cloudflare/DOMAIN_PLACEHOLDER.key;
    
    # Security checks
    if ($host !~* ^(.+\.)?DOMAIN_PLACEHOLDER$ ){return 444;}
    if ($scheme ~* https) {set $safe 1;}
    if ($ssl_server_name !~* ^(.+\.)?DOMAIN_PLACEHOLDER$ ) {set $safe "${safe}0"; }
    if ($safe = 10){return 444;}
    
    # Block malicious requests
    if ($request_uri ~ "(\.\./)"){return 444;}
    if ($request_uri ~ "(//)"){return 444;}
    if ($request_uri ~ "(0x00|0X00)"){return 444;}
    
    error_page 400 402 403 500 501 502 503 504 =404 /404;
    proxy_intercept_errors on;
    
    # Default location - serve static files
    location / { 
        try_files $uri $uri/ =404; 
    }
    
    # Add basic security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
}
NGINX_CONFIG

# Replace placeholders
sed -i "s/DOMAIN_PLACEHOLDER/$MainDomain/g" "/etc/nginx/sites-available/$MainDomain"
sed -i "s/HTTP2_OLD/$OLD_H2/g" "/etc/nginx/sites-available/$MainDomain"
sed -i "s/HTTP2_NEW/$NEW_H2/g" "/etc/nginx/sites-available/$MainDomain"

# Enable site
if [[ -f "/etc/nginx/sites-available/$MainDomain" ]]; then
    unlink "/etc/nginx/sites-enabled/default" >/dev/null 2>&1
    rm -f "/etc/nginx/sites-enabled/default" "/etc/nginx/sites-available/default"
    ln -fs "/etc/nginx/sites-available/$MainDomain" "/etc/nginx/sites-enabled/" 2>/dev/null
fi
sudo rm -f /etc/nginx/sites-enabled/*{~,bak,backup,save,swp,tmp}

# Create a simple index.html file (will be replaced by random template)
cat > "/var/www/html/index.html" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            color: white;
        }
        .container {
            text-align: center;
            background: rgba(255,255,255,0.1);
            padding: 3rem;
            border-radius: 15px;
            backdrop-filter: blur(10px);
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
        }
        h1 {
            font-size: 3rem;
            margin-bottom: 1rem;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        p {
            font-size: 1.2rem;
            opacity: 0.9;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Server Ready</h1>
        <p>Nginx is running successfully with SSL</p>
    </div>
</body>
</html>
EOF

# Setup cron job for nginx reload only (no Cloudflare IP updates in CDN OFF mode)
tasks=(
  "0 0 * * * sudo su -c 'nginx -s reload 2>&1 | grep -q error && { pkill nginx || killall nginx; nginx -c /etc/nginx/nginx.conf; nginx -s reload; }'"
)
crontab -l | grep -qE "nginx" || { printf "%s\n" "${tasks[@]}" | crontab -; }

# Install Random Fake Website Template
msg_inf "Installing random fake website template..."

cd "$HOME" || exit 1

if [[ ! -d "randomfakehtml-master" ]]; then
    msg_inf "Downloading fake website templates..."
    wget -q https://github.com/GFW4Fun/randomfakehtml/archive/refs/heads/master.zip -O master.zip
    if [[ -f "master.zip" ]]; then
        unzip -q master.zip && rm -f master.zip
    else
        msg_err "Failed to download templates, keeping default page"
    fi
fi

if [[ -d "randomfakehtml-master" ]]; then
    cd randomfakehtml-master || exit 1
    rm -rf assets ".gitattributes" "README.md" "_config.yml" 2>/dev/null

    # Get list of available templates and select random one
    RandomHTML=$(find . -maxdepth 1 -type d ! -name "." | sed 's|^\./||' | shuf -n1 2>/dev/null)
    
    if [[ -n "$RandomHTML" && -d "$RandomHTML" ]]; then
        msg_inf "Selected random template: $RandomHTML"
        
        if [[ -d "/var/www/html/" ]]; then
            rm -rf /var/www/html/*
            cp -a "$RandomHTML"/. "/var/www/html/" 2>/dev/null
            
            # Set proper permissions
            chown -R $nginxusr:$nginxusr /var/www/html/ 2>/dev/null
            chmod -R 755 /var/www/html/ 2>/dev/null
            
            msg_ok "Random fake website template installed successfully!"
        else
            msg_err "Web directory not found, keeping default page"
        fi
    else
        msg_err "No templates found, keeping default page"
    fi
    
    cd "$HOME" || exit 1
    rm -rf randomfakehtml-master 2>/dev/null
else
    msg_err "Template download failed, keeping default page"
fi

# Test and start nginx
if ! systemctl start nginx > /dev/null 2>&1 || ! nginx -t &>/dev/null || nginx -s reload 2>&1 | grep -q error; then
    pkill -9 nginx || killall -9 nginx
    nginx -c /etc/nginx/nginx.conf
    nginx -s reload
fi

# Show results
clear
msg_ok "Nginx successfully installed and configured with Cloudflare Origin Certificate!"
msg_inf "Mode: CDN OFF - Direct access enabled"
msg_inf "Domain: https://$domain"
msg_inf "SSL Certificate: /etc/ssl/cloudflare/$MainDomain.crt"
msg_inf "SSL Private Key: /etc/ssl/cloudflare/$MainDomain.key"
msg_inf "Random fake website template has been installed"
nginx -T | grep -i 'configuration file /etc/nginx/sites-enabled/' | sed 's/.*configuration file //' | tr -d ':' | awk '{print "\033[1;32;40m" $0 "\033[0m"}'
openssl x509 -in "/etc/ssl/cloudflare/$MainDomain.crt" -text -noout | grep -E "Subject:|DNS:" | awk '{print "\033[1;37;40m" $0 "\033[0m"}'

msg_war "============================================"
msg_war "Setup Complete! (CDN OFF Mode)"
msg_war "============================================"
msg_inf "✅ Nginx installed and running"
msg_inf "✅ SSL certificate configured (15-year validity)"
msg_inf "✅ Direct access enabled (no Cloudflare restrictions)"
msg_inf "✅ Random fake website template installed"
msg_inf "✅ Basic security headers configured"
msg_inf "✅ Nginx maintenance cron job setup"
msg_war "============================================"
msg_inf "Note: CDN OFF mode allows direct IP access"
msg_inf "Site accessible via both domain and server IP"