ALTER TABLE "session"
  ALTER COLUMN "level" DROP NOT NULL,
  ALTER COLUMN "acr" DROP NOT NULL;

ALTER TABLE "session" ADD CONSTRAINT "session_magic_link_metadata_check"
CHECK (
  CASE WHEN "provider" = 'magic-link'
    THEN "level" IS NULL AND "acr" IS NULL AND "authTime" IS NULL
    ELSE "level" IS NOT NULL AND "level" IN ('L2', 'L3') AND "acr" IS NOT NULL
  END
);
