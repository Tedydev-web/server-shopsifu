# Checklist hoàn thành task

## Trước khi hoàn thành task
1. **Build project**: Chạy `npm run build` để đảm bảo không có lỗi compile
2. **Lint code**: Chạy `npm run lint` để fix code style
3. **Format code**: Chạy `npm run format` để format code
4. **Test (nếu có)**: Chạy `npm run test` để đảm bảo tests pass

## Kiểm tra chất lượng code
- [ ] Code tuân thủ TypeScript guidelines
- [ ] Tuân thủ naming conventions
- [ ] Không có unused imports/variables
- [ ] Proper error handling
- [ ] JSDoc documentation cho public APIs
- [ ] Type safety (không sử dụng any)

## Kiểm tra NestJS architecture
- [ ] Modular structure đúng
- [ ] Proper separation of concerns
- [ ] DTOs được validate
- [ ] Services có business logic rõ ràng
- [ ] Controllers chỉ handle HTTP concerns

## Database considerations
- [ ] Prisma schema được update nếu cần
- [ ] Migrations được tạo nếu có thay đổi schema
- [ ] Không overwrite manual database updates

## Security considerations
- [ ] Proper authentication/authorization
- [ ] Input validation
- [ ] No sensitive data exposure
- [ ] Rate limiting (nếu cần)

## Performance considerations
- [ ] Efficient database queries
- [ ] Proper caching strategy
- [ ] No memory leaks
- [ ] Optimized for production

## Documentation
- [ ] Code comments cho logic phức tạp
- [ ] API documentation (nếu thêm endpoints mới)
- [ ] Update README nếu cần