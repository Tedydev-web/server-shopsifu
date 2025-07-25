/* DO NOT EDIT, file generated by nestjs-i18n */

/* eslint-disable */
/* prettier-ignore */
import { Path } from "nestjs-i18n";
/* prettier-ignore */
export type I18nTranslations = {
    "auth": {
        "auth": {
            "success": {
                "DISABLE_2FA_SUCCESS": string;
                "LOGOUT_SUCCESS": string;
                "REFRESH_TOKEN_SUCCESS": string;
                "SEND_OTP_SUCCESS": string;
                "FORGOT_PASSWORD_SUCCESS": string;
                "LOGIN_SUCCESS": string;
            };
            "error": {
                "INVALID_OTP": string;
                "OTP_EXPIRED": string;
                "FAILED_TO_SEND_OTP": string;
                "EMAIL_ALREADY_EXISTS": string;
                "EMAIL_NOT_FOUND": string;
                "REFRESH_TOKEN_ALREADY_USED": string;
                "UNAUTHORIZED_ACCESS": string;
                "FAILED_TO_GET_GOOGLE_USER_INFO": string;
                "INVALID_TOTP": string;
                "TOTP_ALREADY_ENABLED": string;
                "TOTP_NOT_ENABLED": string;
                "INVALID_TOTP_AND_CODE": string;
                "INVALID_REFRESH_TOKEN": string;
                "REFRESH_TOKEN_REUSED": string;
                "STATE_TOKEN_MISSING": string;
                "ACCESS_TOKEN_REQUIRED": string;
            };
        };
    };
    "brand": {
        "brand": {
            "success": {
                "CREATE_SUCCESS": string;
                "UPDATE_SUCCESS": string;
                "DELETE_SUCCESS": string;
                "GET_SUCCESS": string;
                "GET_DETAIL_SUCCESS": string;
            };
            "error": {
                "NOT_FOUND": string;
                "ALREADY_EXISTS": string;
                "CANNOT_DELETE": string;
            };
        };
        "brandTranslation": {
            "success": {
                "CREATE_SUCCESS": string;
                "UPDATE_SUCCESS": string;
                "DELETE_SUCCESS": string;
                "GET_DETAIL_SUCCESS": string;
            };
            "error": {
                "BRAND_NOT_FOUND": string;
                "LANGUAGE_NOT_FOUND": string;
                "ALREADY_EXISTS": string;
                "CANNOT_DELETE": string;
            };
        };
    };
    "cart": {
        "cart": {
            "success": {
                "CREATE_SUCCESS": string;
                "UPDATE_SUCCESS": string;
                "DELETE_SUCCESS": string;
                "GET_SUCCESS": string;
                "GET_DETAIL_SUCCESS": string;
            };
            "error": {
                "SKU_NOT_FOUND": string;
                "SKU_OUT_OF_STOCK": string;
                "PRODUCT_NOT_FOUND": string;
                "CART_ITEM_NOT_FOUND": string;
                "INVALID_QUANTITY": string;
            };
        };
    };
    "category": {
        "category": {
            "success": {
                "CREATE_SUCCESS": string;
                "UPDATE_SUCCESS": string;
                "DELETE_SUCCESS": string;
                "GET_SUCCESS": string;
                "GET_DETAIL_SUCCESS": string;
            };
            "error": {
                "NOT_FOUND": string;
                "ALREADY_EXISTS": string;
                "CANNOT_DELETE": string;
            };
        };
        "categoryTranslation": {
            "success": {
                "CREATE_SUCCESS": string;
                "UPDATE_SUCCESS": string;
                "DELETE_SUCCESS": string;
                "GET_DETAIL_SUCCESS": string;
            };
            "error": {
                "NOT_FOUND": string;
                "ALREADY_EXISTS": string;
                "CATEGORY_NOT_FOUND": string;
                "LANGUAGE_NOT_FOUND": string;
            };
        };
    };
    "device": {
        "success": {
            "DEVICE_RENAMED": string;
            "DEVICE_REVOKED": string;
            "DEVICE_TRUSTED": string;
            "DEVICE_UNTRUSTED": string;
            "DEVICE_UPDATED": string;
        };
        "error": {
            "DEVICE_NOT_FOUND": string;
            "DEVICE_NOT_BELONG_TO_USER": string;
            "DEVICE_NOT_TRUSTED": string;
            "DEVICE_TRUST_EXPIRED": string;
            "DEVICE_ALREADY_TRUSTED": string;
            "DEVICE_INACTIVE": string;
            "DEVICE_REVOKED": string;
            "DEVICE_LIMIT_EXCEEDED": string;
            "DEVICE_NAME_REQUIRED": string;
            "DEVICE_NAME_TOO_LONG": string;
            "DEVICE_NAME_INVALID": string;
            "INVALID_DEVICE_FINGERPRINT": string;
            "DEVICE_FINGERPRINT_REQUIRED": string;
            "DEVICE_SESSION_NOT_FOUND": string;
            "DEVICE_SESSION_EXPIRED": string;
            "DEVICE_SESSION_REVOKED": string;
            "DEVICE_CREATION_FAILED": string;
            "DEVICE_UPDATE_FAILED": string;
            "DEVICE_DELETION_FAILED": string;
            "DEVICE_REVOKE_FAILED": string;
        };
    };
    "discount": {
        "discount": {
            "success": {
                "CREATE_SUCCESS": string;
                "GET_SUCCESS": string;
                "UPDATE_SUCCESS": string;
                "DELETE_SUCCESS": string;
                "CALCULATE_SUCCESS": string;
                "GET_AVAILABLE_SUCCESS": string;
            };
            "error": {
                "CODE_EXISTS": string;
                "NOT_FOUND": string;
                "FORBIDDEN": string;
                "PRODUCT_OWNERSHIP": string;
                "USAGE_LIMIT_EXCEEDED": string;
                "EXPIRED": string;
                "INVALID_DATE_RANGE": string;
                "SHOP_VOUCHER_WITH_PRODUCTS": string;
                "PRODUCT_VOUCHER_WITHOUT_PRODUCTS": string;
                "INVALID_MAX_DISCOUNT_VALUE": string;
                "INVALID_CODE_FORMAT": string;
            };
        };
    };
    "global": {
        "global": {
            "success": {
                "GET_SUCCESS": string;
                "GET_DETAIL_SUCCESS": string;
                "CREATE_SUCCESS": string;
                "UPDATE_SUCCESS": string;
                "DELETE_SUCCESS": string;
            };
            "error": {
                "NOT_FOUND_RECORD": string;
                "INVALID_PASSWORD": string;
                "UNAUTHORIZED": string;
                "FORBIDDEN": string;
                "SESSION_NOT_FOUND": string;
                "TOKEN_BLACKLISTED": string;
                "USER_NOT_ACTIVE": string;
                "INSUFFICIENT_PERMISSIONS": string;
                "MISSING_ACCESS_TOKEN": string;
            };
        };
    };
    "language": {
        "language": {
            "success": {
                "CREATE_SUCCESS": string;
                "UPDATE_SUCCESS": string;
                "DELETE_SUCCESS": string;
                "GET_SUCCESS": string;
                "GET_DETAIL_SUCCESS": string;
            };
            "error": {
                "NOT_FOUND": string;
                "ALREADY_EXISTS": string;
                "CANNOT_DELETE": string;
            };
        };
    };
    "media": {
        "media": {
            "success": {
                "UPLOAD_SUCCESS": string;
                "GET_PRESIGNED_URL_SUCCESS": string;
                "DELETE_SUCCESS": string;
            };
            "error": {
                "UPLOAD_FAILED": string;
                "FILE_NOT_FOUND": string;
                "INVALID_FILE_TYPE": string;
                "FILE_TOO_LARGE": string;
                "PRESIGNED_URL_FAILED": string;
                "S3_ERROR": string;
            };
        };
    };
    "order": {
        "order": {
            "success": {
                "CREATE_SUCCESS": string;
                "UPDATE_SUCCESS": string;
                "DELETE_SUCCESS": string;
                "GET_SUCCESS": string;
                "GET_DETAIL_SUCCESS": string;
                "CANCEL_SUCCESS": string;
                "CALCULATE_SUCCESS": string;
            };
            "error": {
                "NOT_FOUND": string;
                "ALREADY_EXISTS": string;
                "CANNOT_CANCEL": string;
                "INVALID_STATUS": string;
                "INSUFFICIENT_STOCK": string;
                "PRODUCT_NOT_FOUND": string;
                "NOT_FOUND_CART_ITEM": string;
                "SKU_NOT_BELONG_TO_SHOP": string;
                "OUT_OF_STOCK_SKU": string;
            };
        };
    };
    "payment": {
        "payment": {
            "success": {
                "RECEIVER_SUCCESS": string;
            };
        };
    };
    "permission": {
        "permission": {
            "success": {
                "CREATE_SUCCESS": string;
                "UPDATE_SUCCESS": string;
                "DELETE_SUCCESS": string;
                "GET_SUCCESS": string;
                "GET_DETAIL_SUCCESS": string;
            };
            "error": {
                "NOT_FOUND": string;
                "ALREADY_EXISTS": string;
            };
        };
    };
    "product": {
        "product": {
            "success": {
                "CREATE_SUCCESS": string;
                "UPDATE_SUCCESS": string;
                "DELETE_SUCCESS": string;
                "GET_SUCCESS": string;
                "GET_DETAIL_SUCCESS": string;
            };
            "error": {
                "NOT_FOUND": string;
                "BRAND_NOT_FOUND": string;
                "CATEGORY_NOT_FOUND": string;
            };
        };
        "productTranslation": {
            "success": {
                "CREATE_SUCCESS": string;
                "UPDATE_SUCCESS": string;
                "DELETE_SUCCESS": string;
                "GET_DETAIL_SUCCESS": string;
            };
            "error": {
                "NOT_FOUND": string;
                "ALREADY_EXISTS": string;
                "PRODUCT_NOT_FOUND": string;
                "LANGUAGE_NOT_FOUND": string;
                "CATEGORY_NOT_FOUND": string;
            };
        };
    };
    "profile": {
        "success": {
            "GET_PROFILE": string;
            "UPDATE_PROFILE": string;
            "CHANGE_PASSWORD": string;
            "GET_ADDRESSES": string;
            "GET_ADDRESS_DETAIL": string;
            "CREATE_ADDRESS": string;
            "UPDATE_ADDRESS": string;
            "DELETE_ADDRESS": string;
            "SET_DEFAULT_ADDRESS": string;
            "GET_STATISTICS": string;
        };
        "error": {
            "NOT_FOUND": string;
            "INVALID_PASSWORD": string;
            "UPDATE_FAILED": string;
            "CHANGE_PASSWORD_FAILED": string;
            "ADDRESS_NOT_FOUND": string;
            "ADDRESS_ACCESS_DENIED": string;
            "CREATE_ADDRESS_FAILED": string;
            "UPDATE_ADDRESS_FAILED": string;
            "DELETE_ADDRESS_FAILED": string;
            "SET_DEFAULT_ADDRESS_FAILED": string;
            "GET_STATISTICS_FAILED": string;
        };
    };
    "review": {
        "review": {
            "success": {
                "GET_SUCCESS": string;
                "CREATE_SUCCESS": string;
                "UPDATE_SUCCESS": string;
            };
        };
    };
    "role": {
        "role": {
            "success": {
                "CREATE_SUCCESS": string;
                "UPDATE_SUCCESS": string;
                "DELETE_SUCCESS": string;
                "GET_SUCCESS": string;
                "GET_DETAIL_SUCCESS": string;
            };
            "error": {
                "NOT_FOUND": string;
                "ALREADY_EXISTS": string;
                "DELETED_PERMISSION_INCLUDED": string;
                "OPERATION_FAILED": string;
                "CANNOT_UPDATE_DEFAULT_ROLE": string;
                "CANNOT_DELETE_DEFAULT_ROLE": string;
                "PROHIBITED_ACTION_ON_BASE_ROLE": string;
            };
        };
    };
    "user": {
        "user": {
            "success": {
                "CREATE_SUCCESS": string;
                "UPDATE_SUCCESS": string;
                "DELETE_SUCCESS": string;
                "GET_SUCCESS": string;
                "GET_DETAIL_SUCCESS": string;
            };
            "error": {
                "NOT_FOUND": string;
                "ALREADY_EXISTS": string;
                "CANNOT_DELETE": string;
                "CANNOT_UPDATE_ADMIN_USER": string;
                "CANNOT_DELETE_ADMIN_USER": string;
                "ROLE_NOT_FOUND": string;
            };
        };
    };
};
/* prettier-ignore */
export type I18nPath = Path<I18nTranslations>;
