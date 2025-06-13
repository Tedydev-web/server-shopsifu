-- Migration script to update AUTHENTICATOR_APP to TOTP
UPDATE "User" 
SET two_factor_method = 'TOTP' 
WHERE two_factor_method = 'AUTHENTICATOR_APP';
