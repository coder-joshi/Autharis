import { pgEnum, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";

export const userStatus = pgEnum("user_status", ["active", "disabled"]);
export const userRole = pgEnum("user_role", ["user", "admin"]);

export const users = pgTable("users", {
  id: uuid("id").primaryKey().defaultRandom(),
  email: text("email").notNull(),
  emailNormalized: text("email_normalized").notNull().unique(),
  emailVerifiedAt: timestamp("email_verified_at", {
    withTimezone: true,
  }),
  passwordHash: text("password_hash"),
  displayName: text("display_name"),
  status: userStatus("status").notNull().default("active"),
  role: userRole("role").notNull().default("user"),
  createdAt: timestamp("created_at", {
    withTimezone: true,
  })
    .notNull()
    .defaultNow(),
  updatedAt: timestamp("updated_at", {
    withTimezone: true,
  })
    .notNull()
    .defaultNow()
    .$onUpdate(() => new Date()),
});
