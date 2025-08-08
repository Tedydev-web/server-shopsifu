#!/bin/bash

# Script kiểm tra thời hạn SSL certificates
# Chạy với: bash scripts/check-cert-expiry.sh

set -e

echo "📅 Kiểm tra thời hạn SSL certificates..."

# Function để tính số ngày còn lại
days_until_expiry() {
    local cert_file=$1
    local expiry_date=$(openssl x509 -in "$cert_file" -text -noout | grep "Not After" | cut -d: -f2-)
    local expiry_timestamp=$(date -d "$expiry_date" +%s)
    local current_timestamp=$(date +%s)
    local days_left=$(( (expiry_timestamp - current_timestamp) / 86400 ))
    echo $days_left
}

# Kiểm tra từng domain
for domain in api grafana prometheus; do
    cert_file="nginx/ssl/$domain/fullchain.pem"

    if [ -f "$cert_file" ]; then
        echo "$domain.shopsifu.live:"

        # Lấy thông tin certificate
        subject=$(openssl x509 -in "$cert_file" -text -noout | grep "Subject:" | head -1)
        not_after=$(openssl x509 -in "$cert_file" -text -noout | grep "Not After" | head -1)

        echo "  Subject: $subject"
        echo "  Expires: $not_after"

        # Tính số ngày còn lại
        days_left=$(days_until_expiry "$cert_file")

        if [ $days_left -gt 30 ]; then
            echo "  Status: ✅ OK ($days_left days remaining)"
        elif [ $days_left -gt 7 ]; then
            echo "  Status: ⚠️  WARNING ($days_left days remaining)"
        else
            echo "  Status: ❌ CRITICAL ($days_left days remaining)"
        fi

        echo ""
    else
        echo "$domain.shopsifu.live: ❌ Certificate not found"
        echo ""
    fi
done

# Tóm tắt
echo "📋 Tóm tắt:"
total_certs=0
expired_certs=0
warning_certs=0
ok_certs=0

for domain in api grafana prometheus; do
    cert_file="nginx/ssl/$domain/fullchain.pem"

    if [ -f "$cert_file" ]; then
        total_certs=$((total_certs + 1))
        days_left=$(days_until_expiry "$cert_file")

        if [ $days_left -le 7 ]; then
            expired_certs=$((expired_certs + 1))
        elif [ $days_left -le 30 ]; then
            warning_certs=$((warning_certs + 1))
        else
            ok_certs=$((ok_certs + 1))
        fi
    fi
done

echo "- Total certificates: $total_certs"
echo "- OK (>30 days): $ok_certs"
echo "- Warning (7-30 days): $warning_certs"
echo "- Critical (<7 days): $expired_certs"

# Đề xuất hành động
if [ $expired_certs -gt 0 ]; then
    echo ""
    echo "🚨 HÀNH ĐỘNG CẦN THIẾT:"
    echo "Chạy: bash scripts/renew-ssl.sh"
elif [ $warning_certs -gt 0 ]; then
    echo ""
    echo "⚠️  CẢNH BÁO:"
    echo "Một số certificates sẽ hết hạn sớm. Cân nhắc renew sớm."
else
    echo ""
    echo "✅ TẤT CẢ OK:"
    echo "Tất cả certificates đều còn hạn dài."
fi

echo ""
echo "📅 Auto-renewal schedule:"
echo "- Ngày 1 và 15 hàng tháng lúc 12:00"
echo "- Script: scripts/renew-ssl.sh"
echo "- Manual renew: bash scripts/renew-ssl.sh"
