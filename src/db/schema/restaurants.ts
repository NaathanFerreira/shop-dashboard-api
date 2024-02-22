import { uuid, text, timestamp, pgTable } from "drizzle-orm/pg-core";
import { users } from './users'
import { relations } from "drizzle-orm";


export const restaurants = pgTable("restaurants", {
  id: uuid("id").primaryKey(),
  name: text("name").notNull(),
  description: text("description"),
  managerId: uuid('manager_id').references(() => users.id, {
    onDelete: 'set null',
  }),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
});

// a restaurant has one manager
export const restaurantsRelations = relations(restaurants, ({ one }) => {
  return {
    manager: one(users, {
      fields: [restaurants.managerId],
      references: [users.id],
      relationName: 'restaurant_name'
    })
  }
})