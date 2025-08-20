# Checklist khi hoàn tất tác vụ
- Chạy `npm run build` để đảm bảo build xanh.
- Chạy `npm test` nếu có, hoặc smoke test nhanh qua `curl` endpoint health: `GET /health`.
- Chạy `npm run lint` và `npm run format` đảm bảo code sạch.
- Kiểm tra migration Prisma không ghi đè thay đổi DB thủ công; tránh dùng `db push` trên prod; dùng `migrate:prod`.
- Nếu thêm endpoint/module mới, cập nhật seed/permissions/languages nếu liên quan.
- Commit tuân thủ commitlint (config conventional).