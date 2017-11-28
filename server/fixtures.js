export const email = "test@example.com";
export const password = "testtest";

if (Meteor.users.find().count() === 0) {
  Accounts.createUser({ email, password });
}
