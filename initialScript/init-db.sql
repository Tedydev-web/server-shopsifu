-- Tạo database nếu chưa tồn tại
SELECT 'CREATE DATABASE shopsifu'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'shopsifu')\gexec

-- Kết nối vào database shopsifu
\c shopsifu;

-- Tạo extension nếu cần
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
