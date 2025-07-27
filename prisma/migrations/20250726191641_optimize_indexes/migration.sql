-- DropIndex
DROP INDEX "Address_deletedAt_idx";

-- DropIndex
DROP INDEX "Review_rating_idx";

-- DropIndex
DROP INDEX "User_status_idx";

-- CreateIndex
CREATE INDEX "CartItem_skuId_idx" ON "CartItem"("skuId");

-- CreateIndex
CREATE INDEX "Order_userId_status_idx" ON "Order"("userId", "status");

-- CreateIndex
CREATE INDEX "Product_publishedAt_deletedAt_idx" ON "Product"("publishedAt", "deletedAt");
