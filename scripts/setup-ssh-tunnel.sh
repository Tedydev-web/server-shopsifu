#!/bin/bash

# Script setup SSH tunnel cho PostgreSQL
# Chạy với: bash scripts/setup-ssh-tunnel.sh

set -e

echo "🔗 Setup SSH tunnel cho PostgreSQL..."

# 1. Tạo SSH config
echo "📝 Tạo SSH config..."
mkdir -p ~/.ssh
cat > ~/.ssh/config << EOF
Host shopsifu-vps
    HostName 103.147.186.84
    User tedydev
    Port 22
    IdentityFile ~/.ssh/id_rsa
    ServerAliveInterval 60
    ServerAliveCountMax 3
    Compression yes
    TCPKeepAlive yes
EOF

# 2. Tạo script kết nối PostgreSQL
echo "📝 Tạo script kết nối PostgreSQL..."
cat > scripts/connect-postgres.sh << 'EOF'
#!/bin/bash

# Script kết nối PostgreSQL qua SSH tunnel
# Chạy với: bash scripts/connect-postgres.sh

set -e

echo "🔗 Kết nối PostgreSQL qua SSH tunnel..."

# Kiểm tra SSH tunnel
if ! pgrep -f "ssh.*-L.*5432" > /dev/null; then
    echo "🚀 Tạo SSH tunnel..."
    ssh -f -N -L 5432:localhost:5432 shopsifu-vps
    sleep 2
fi

# Test kết nối
echo "🧪 Test kết nối PostgreSQL..."
if pg_isready -h localhost -p 5432 -U shopsifu; then
    echo "✅ PostgreSQL đã sẵn sàng!"
    echo ""
    echo "📋 Connection info:"
    echo "Host: localhost"
    echo "Port: 5432"
    echo "Database: shopsifu"
    echo "Username: shopsifu"
    echo "Password: Shopsifu2025@@"
    echo ""
    echo "🔧 Cách sử dụng:"
    echo "1. psql -h localhost -p 5432 -U shopsifu -d shopsifu"
    echo "2. pgAdmin: localhost:5432"
    echo "3. DBeaver: localhost:5432"
    echo ""
    echo "🛑 Để dừng tunnel: pkill -f 'ssh.*-L.*5432'"
else
    echo "❌ Không thể kết nối PostgreSQL"
    exit 1
fi
EOF

chmod +x scripts/connect-postgres.sh

# 3. Tạo script backup/restore
echo "📝 Tạo script backup/restore..."
cat > scripts/backup-postgres.sh << 'EOF'
#!/bin/bash

# Script backup PostgreSQL
# Chạy với: bash scripts/backup-postgres.sh

set -e

echo "💾 Backup PostgreSQL..."

# Tạo SSH tunnel
ssh -f -N -L 5432:localhost:5432 shopsifu-vps
sleep 2

# Backup
BACKUP_DIR="./backups"
mkdir -p $BACKUP_DIR
BACKUP_FILE="$BACKUP_DIR/shopsifu_$(date +%Y%m%d_%H%M%S).sql"

echo "📦 Backup database..."
PGPASSWORD=Shopsifu2025@@ pg_dump -h localhost -p 5432 -U shopsifu -d shopsifu > $BACKUP_FILE

# Nén backup
gzip $BACKUP_FILE

echo "✅ Backup hoàn tất: ${BACKUP_FILE}.gz"

# Dừng tunnel
pkill -f "ssh.*-L.*5432"
EOF

chmod +x scripts/backup-postgres.sh

# 4. Tạo script restore
echo "📝 Tạo script restore..."
cat > scripts/restore-postgres.sh << 'EOF'
#!/bin/bash

# Script restore PostgreSQL
# Chạy với: bash scripts/restore-postgres.sh <backup_file>

set -e

if [ -z "$1" ]; then
    echo "❌ Vui lòng chỉ định file backup"
    echo "Usage: bash scripts/restore-postgres.sh <backup_file>"
    exit 1
fi

BACKUP_FILE=$1

if [ ! -f "$BACKUP_FILE" ]; then
    echo "❌ File backup không tồn tại: $BACKUP_FILE"
    exit 1
fi

echo "🔄 Restore PostgreSQL từ: $BACKUP_FILE"

# Tạo SSH tunnel
ssh -f -N -L 5432:localhost:5432 shopsifu-vps
sleep 2

# Restore
echo "📦 Restore database..."
if [[ $BACKUP_FILE == *.gz ]]; then
    gunzip -c $BACKUP_FILE | PGPASSWORD=Shopsifu2025@@ psql -h localhost -p 5432 -U shopsifu -d shopsifu
else
    PGPASSWORD=Shopsifu2025@@ psql -h localhost -p 5432 -U shopsifu -d shopsifu < $BACKUP_FILE
fi

echo "✅ Restore hoàn tất!"

# Dừng tunnel
pkill -f "ssh.*-L.*5432"
EOF

chmod +x scripts/restore-postgres.sh

# 5. Tạo connection config cho tools
echo "📝 Tạo connection config..."
mkdir -p config/database

# DBeaver config
cat > config/database/dbeaver-connection.json << EOF
{
  "name": "Shopsifu VPS",
  "driver": "postgresql",
  "host": "localhost",
  "port": 5432,
  "database": "shopsifu",
  "username": "shopsifu",
  "password": "Shopsifu2025@@",
  "savePassword": true,
  "showAllSchemas": true,
  "showSystemObjects": false
}
EOF

# pgAdmin config
cat > config/database/pgadmin-servers.json << EOF
{
  "Servers": {
    "1": {
      "Name": "Shopsifu VPS",
      "Group": "Servers",
      "Host": "localhost",
      "Port": 5432,
      "MaintenanceDB": "shopsifu",
      "Username": "shopsifu",
      "SSLMode": "prefer",
      "PassFile": "/tmp/.pgpass"
    }
  }
}
EOF

echo "✅ Setup SSH tunnel hoàn tất!"
echo ""
echo "📋 Cách sử dụng:"
echo "1. Kết nối: bash scripts/connect-postgres.sh"
echo "2. Backup: bash scripts/backup-postgres.sh"
echo "3. Restore: bash scripts/restore-postgres.sh <backup_file>"
echo "4. Dừng tunnel: pkill -f 'ssh.*-L.*5432'"
echo ""
echo "🔧 Connection info:"
echo "Host: localhost"
echo "Port: 5432"
echo "Database: shopsifu"
echo "Username: shopsifu"
echo "Password: Shopsifu2025@@"
