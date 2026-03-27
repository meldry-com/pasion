CREATE TABLE "user_phones" (
    "user_phone_id" UUID PRIMARY KEY,
    "user_id" UUID NOT NULL REFERENCES "users" ("user_id") ON DELETE CASCADE,
    "phone" TEXT NOT NULL,
    "created_at" TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX "idx_user_phones_user_id" ON "user_phones" ("user_id");
CREATE INDEX "idx_user_phones_phone" ON "user_phones" ("phone");

CREATE TABLE "user_phone_authentications" (
    "user_phone_authentication_id" UUID PRIMARY KEY,
    "user_registration_id" UUID REFERENCES "user_registrations" ("user_registration_id") ON DELETE CASCADE,
    "phone" TEXT NOT NULL,
    "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,
    "completed_at" TIMESTAMP WITH TIME ZONE
);

CREATE TABLE "user_phone_authentication_codes" (
    "user_phone_authentication_code_id" UUID PRIMARY KEY,
    "user_phone_authentication_id" UUID NOT NULL
        REFERENCES "user_phone_authentications" ("user_phone_authentication_id") ON DELETE CASCADE,
    "code" TEXT NOT NULL,
    "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,
    "expires_at" TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX "idx_user_phone_auth_codes_auth_id" ON "user_phone_authentication_codes" ("user_phone_authentication_id");

ALTER TABLE "user_registrations"
    ADD COLUMN "phone_authentication_id" UUID
        REFERENCES "user_phone_authentications" ("user_phone_authentication_id")
        ON DELETE SET NULL;
