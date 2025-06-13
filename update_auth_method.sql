-- Cập nhật tất cả records từ AUTHENTICATOR_APP sang TOTP
UPDATE "User" SET "two_factor_method" = 'TOTP' WHERE "two_factor_method" = 'AUTHENTICATOR_APP';
