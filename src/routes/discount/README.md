# Discount Module API

This document provides an overview of the API endpoints available in the Discount module. This module is responsible for managing all discount-related operations, including platform-wide vouchers and shop-specific vouchers.

## Roles

-   **Admin**: Can create, read, update, and delete any discount, including platform-wide (`shopId: null`) and shop-specific vouchers.
-   **Seller**: Can create, read, update, and delete discounts for their own shop only. The `shopId` will be automatically set to the seller's `userId`.
-   **Client/Guest**: Can view available discounts and verify them for their orders.

---

## Public Endpoints (for Client/Guest)

Base Path: `/discounts`

### 1. Get Available Discounts

-   **Endpoint**: `GET /available`
-   **Description**: Retrieves all available discounts for a given context (platform-wide and/or shop-specific). This endpoint will never return a 404 error; instead, it will return empty arrays if no discounts are available.
-   **Query Parameters**:
    -   `shopId` (string, optional): The ID of the shop to get vouchers for. If set to `null` or omitted, it will fetch platform-wide vouchers.
    -   `orderValue` (number, optional, default: 0): The current order value to check against the discount's `minOrderValue`.
    -   `productId` (string, optional): The ID of a specific product to check for product-specific vouchers.
    -   `isPublic` (boolean, optional, default: true): Filters for public discounts.
    -   `status` (string, optional, default: 'ACTIVE'): Filters by discount status.
-   **Response**: `GetAvailableDiscountsResDTO`
    -   `data.available`: An array of `Discount` objects that the user can apply.
    -   `data.unavailable`: An array of `Discount` objects that are not applicable, each with a `reason` field explaining why.

### 2. Verify a Discount Code

-   **Endpoint**: `POST /verify`
-   **Description**: Verifies if a discount code is valid for the current order and calculates the discount amount.
-   **Request Body**: `VerifyDiscountBodyDTO`
    -   `code` (string, required): The discount code to verify.
    -   `orderValue` (number, required): The total value of the order.
    -   `cart` (array, optional): Detailed cart information to check against specific conditions.
-   **Response**: `VerifyDiscountResDTO`
    -   `data.discountAmount`: The calculated amount to be discounted.
    -   `data.discount`: Details of the applied discount.

### 3. Get Discount Detail

-   **Endpoint**: `GET /:discountId`
-   **Description**: Retrieves the details of a specific public discount.
-   **Response**: `GetDiscountDetailResDTO`

---

## Management Endpoints (for Admin/Seller)

Base Path: `/manage-discount/discounts`

### 1. List Discounts (for Admin/Seller)

-   **Endpoint**: `GET /`
-   **Description**: Lists discounts based on the user's role.
    -   **Admin**: Can list all discounts by providing `shopId` or `null` (for platform-wide).
    -   **Seller**: Will only see discounts for their own shop (`shopId` is automatically filtered).
-   **Query Parameters**: `GetManageDiscountsQueryDTO`
-   **Response**: `GetDiscountsResDTO` (paginated)

### 2. Create a Discount

-   **Endpoint**: `POST /`
-   **Description**: Creates a new discount.
    -   **Admin**: Can create a platform-wide voucher by setting `shopId` to `null` or a shop-specific voucher by providing a `shopId`.
    -   **Seller**: Creates a voucher for their own shop; `shopId` is automatically set to their user ID.
-   **Request Body**: `CreateDiscountBodyDTO`
-   **Response**: `GetDiscountDetailResDTO`

### 3. Update a Discount

-   **Endpoint**: `PUT /:discountId`
-   **Description**: Updates an existing discount. Access is restricted to the discount owner (Seller) or an Admin.
-   **Request Body**: `UpdateDiscountBodyDTO`
-   **Response**: `UpdateDiscountResDTO`

### 4. Delete a Discount

-   **Endpoint**: `DELETE /:discountId`
-   **Description**: Deletes a discount (soft delete). Access is restricted to the discount owner (Seller) or an Admin.
-   **Response**: `MessageResDTO`
